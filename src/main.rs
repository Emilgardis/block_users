#![feature(option_result_contains)]
use std::io::BufRead;

use anyhow::Context;
use clap::{ArgGroup, ArgSettings, Clap};
use twitch_api2::{
    helix::{
        make_stream,
        users::{block_user, get_user_block_list},
    },
    twitch_oauth2::{self, UserToken},
    types::{self, UserName},
};

#[derive(Clap, Debug)]
#[clap(about, version,
    group = ArgGroup::new("token").multiple(false).required(false),
    group = ArgGroup::new("service").multiple(true), 
)]
pub struct Opts {
    /// File to read users from
    #[clap(long, required_unless_present = "users", conflicts_with = "users")]
    pub file: Option<std::path::PathBuf>,
    /// Skip content after first comma in a line, ignoring that data
    #[clap(long)]
    pub skip_comma: bool,
    /// Always check previously blocked users before sending blocks.
    #[clap(long)]
    pub check_first: bool,
    /// Unblock users instead of blocking.
    #[clap(long)]
    pub unblock: bool,
    /// Users to block.
    #[clap(
        long,
        required_unless_present = "file",
        conflicts_with = "file",
        multiple_values = true
    )]
    pub users: Option<Vec<String>>,
    /// OAuth2 Access token.
    #[clap(long, env, setting = ArgSettings::HideEnvValues, group = "token",
        validator = is_token, required_unless_present = "service",
    )]
    pub access_token: Option<Secret>,
    /// Name of channel to get token for.
    #[clap(long, env, setting = ArgSettings::HideEnvValues, group = "service",
        required_unless_present = "token"
    )]
    pub channel_login: Option<String>,
    /// URL to service that provides OAuth2 token. Called on start, can have {login} in url to replace with [channel_login].
    #[clap(long, env, setting = ArgSettings::HideEnvValues, group = "token", 
        validator = url::Url::parse,
        required_unless_present = "token"
    )]
    pub oauth2_service_url: Option<String>,
    /// Bearer key for authorizing on the OAuth2 service url.
    #[clap(long, env, setting = ArgSettings::HideEnvValues, group = "service"
    )]
    pub oauth2_service_key: Option<Secret>,
    /// Grab token by pointer. See https://tools.ietf.org/html/rfc6901
    #[clap(long, env, setting = ArgSettings::HideEnvValues, group = "service", 
        default_value_if("oauth2-service-url", None, Some("/access_token"))
    )]
    pub oauth2_service_pointer: Option<String>,
}

#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    fn secret(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for Secret {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[secret]")
    }
}

pub fn is_token(s: &str) -> anyhow::Result<()> {
    if s.starts_with("oauth:") {
        anyhow::bail!("token should not have `oauth:` as a prefix")
    }
    if s.len() != 30 {
        anyhow::bail!("token needs to be 30 characters long")
    }
    Ok(())
}

pub async fn make_token<'a>(
    client: &'a impl twitch_oauth2::client::Client<'a>,
    token: impl Into<twitch_oauth2::AccessToken>,
) -> Result<UserToken, anyhow::Error> {
    UserToken::from_existing(client, token.into(), None, None)
        .await
        .context("could not use access token")
        .map_err(Into::into)
}

pub async fn get_access_token(
    client: &reqwest::Client,
    opts: &crate::Opts,
) -> Result<UserToken, anyhow::Error> {
    if let Some(ref access_token) = opts.access_token {
        make_token(client, access_token.secret().to_string()).await
    } else if let (Some(ref oauth_service_url), Some(ref pointer)) =
        (&opts.oauth2_service_url, &opts.oauth2_service_pointer)
    {
        tracing::info!(
            "using oauth service on `{}` to get oauth token",
            oauth_service_url
        );

        let oauth_service_url = oauth_service_url.replace(
            "{login}",
            &opts
                .channel_login
                .clone()
                .expect("channel-login is required, this is a clap bug"),
        );
        let oauth_service_url = &*oauth_service_url;
        tracing::info!("transformed to `{}`", oauth_service_url);

        let mut request = client.get(oauth_service_url);
        if let Some(ref key) = opts.oauth2_service_key {
            request = request.bearer_auth(key.secret());
        }
        let request = request.build()?;
        tracing::debug!("request: {:?}", request);

        match client.execute(request).await {
            Ok(response)
                if !(response.status().is_client_error()
                    || response.status().is_server_error()) =>
            {
                let service_response: serde_json::Value = response
                    .json()
                    .await
                    .context("when transforming oauth service response to json")?;
                make_token(
                    client,
                    service_response
                        .pointer(pointer)
                        .with_context(|| format!("could not get a field on `{}`", pointer))?
                        .as_str()
                        .context("token is not a string")?
                        .to_string(),
                )
                .await
            }
            Ok(response_error) => {
                let status = response_error.status();
                let error = response_error.text().await?;
                anyhow::bail!(
                    "oauth service returned error code: {} with body: {:?}",
                    status,
                    error
                );
            }
            Err(e) => {
                Err(e).with_context(|| format!("calling oauth service on `{}`", &oauth_service_url))
            }
        }
    } else {
        panic!("got empty vals for token cli group")
    }
}

#[tokio::main]
async fn main() {
    let _ = dotenv::dotenv().with_context(|| "couldn't load .env file"); //ignore error
    let s = tracing_subscriber::FmtSubscriber::builder()
        .compact()
        .with_thread_names(false)
        .with_thread_ids(false)
        .with_ansi(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(s).unwrap();
    let opts = Opts::parse();
    tracing::info!(
        "App started!\n{}",
        Opts::try_parse_from(&["app", "--version"])
            .unwrap_err()
            .to_string()
    );

    match run(&opts).await {
        Ok(_) => {}
        Err(err) => {
            tracing::error!(Error = %err, "Could not handle message");
            for err in <anyhow::Error>::chain(&err).skip(1) {
                tracing::error!(Error = %err, "Caused by");
            }
        }
    }
}

pub async fn run(opts: &Opts) -> anyhow::Result<()> {
    use futures::{StreamExt, TryStreamExt};
    let client: twitch_api2::HelixClient<reqwest::Client> = twitch_api2::HelixClient::default();
    let token = get_access_token(&client.clone_client(), opts).await?;
    let token = std::sync::Arc::new(token);

    let blocking: Vec<types::Nickname> = match (&opts.file, &opts.users) {
        (Some(file), None) if !opts.skip_comma => std::fs::read(&file)?
            .lines()
            .map(|r| r.map(types::Nickname::from))
            .collect::<Result<_, _>>()?,
        (Some(file), None) if opts.skip_comma => std::fs::read(&file)?
            .lines()
            .map(|r| r.map(|s| types::Nickname::from(s.split_once(',').unwrap_or_default().0)))
            .collect::<Result<_, _>>()?,
        (None, Some(users)) => users.iter().map(|s| s.as_str().into()).collect(),
        _ => anyhow::bail!("can't specify a user and a file at the same time"),
    };

    if opts.unblock {
        for user in blocking {
            unblock_user(&client, &user, &token).await?
        }
        return Ok(());
    }

    let blocked_req = get_user_block_list::GetUserBlockListRequest::builder()
        .broadcaster_id(token.user_id.clone())
        .build();
    let previously_blocked = std::sync::Arc::new(tokio::sync::Mutex::new(vec![]));
    let mut first_run = true;
    loop {
        let previously_blocked = previously_blocked.clone();
        let mut blocked: Vec<UserName> = {
            let pb_lock = previously_blocked.lock().await;
            pb_lock.clone()
        };

        let last = previously_blocked.lock().await.last().cloned();
        if !first_run || opts.check_first {
            // We check blocks one time again before calling api, since we might have hit only suspened/non existing accounts
            if !blocking.iter().any(|s| !blocked.contains(s)) {
                tracing::info!("nothing more to block");
                break;
            }
            tracing::info!("checking blocked users");
            blocked.extend(
                make_stream(blocked_req.clone(), &*token, &client, |s| {
                    s.into_iter().map(|u| u.user_login).collect()
                })
                .try_take_while(|n| futures::future::ready(Ok(!last.as_deref().contains(&n))))
                .try_collect::<Vec<_>>()
                .await?,
            );
        }
        let to_block = blocking
            .clone()
            .into_iter()
            .filter(|s| !blocked.contains(s))
            .collect::<Vec<_>>();
        if to_block.is_empty() {
            tracing::info!("nothing more to block");
            break;
        }
        tracing::info!("blocking {} users", to_block.len());
        if first_run {
            first_run = false;
        } else {
            tracing::info!("waiting 10 seconds, not all users were blocked");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        };

        futures::stream::iter(to_block)
            .map(Ok)
            .try_for_each_concurrent(10, |n| {
                let previously_blocked = previously_blocked.clone();
                let client = client.clone();
                let token = token.clone();
                async move {
                    match block_user(&client.clone(), &n, &token.clone()).await? {
                        Exists::Yes => Ok::<_, anyhow::Error>(()),
                        Exists::No(l) => {
                            let mut pb = previously_blocked.lock().await;
                            pb.push(l);
                            Ok(())
                        }
                    }
                }
            })
            .await?;
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exists {
    Yes,
    No(UserName),
}

pub async fn block_user<'c, C: twitch_api2::client::Client<'c> + Sync + 'c>(
    client: &'c twitch_api2::HelixClient<'c, C>,
    user_login: &types::UserNameRef,
    token: &twitch_oauth2::UserToken,
) -> anyhow::Result<Exists> {
    let user = match client
        .get_user_from_login(user_login.to_owned(), token)
        .await?
    {
        Some(u) => u,
        None if user_login
            .as_str()
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_digit()) =>
        {
            match client.get_user_from_id(user_login.as_str(), token).await? {
                Some(u) => u,
                None => {
                    tracing::info!(user_login=%user_login, "user does not exist");
                    return Ok(Exists::No(user_login.to_owned()));
                }
            }
        }
        _ => {
            tracing::info!(user_login=%user_login, "user does not exist");
            return Ok(Exists::No(user_login.to_owned()));
        }
    };
    let req = block_user::BlockUserRequest::builder()
        .target_user_id(user.id)
        .reason(block_user::Reason::Other)
        .source_context(block_user::SourceContext::Chat)
        .build();

    let _ = client.req_put(req, <_>::default(), token).await?;
    tracing::info!("blocked {:?}", user.login);
    Ok(Exists::Yes)
}

pub async fn unblock_user<'c, C: twitch_api2::client::Client<'c> + Sync + 'c>(
    client: &'c twitch_api2::HelixClient<'c, C>,
    user_login: &types::UserNameRef,
    token: &twitch_oauth2::UserToken,
) -> anyhow::Result<()> {
    use twitch_api2::helix::users::unblock_user;
    let user = client
        .get_user_from_login(user_login.to_owned(), token)
        .await?
        .unwrap();
    let req = unblock_user::UnblockUserRequest::builder()
        .target_user_id(user.id)
        .build();

    let _ = client.req_delete(req, token).await?;
    tracing::info!("unblocked {:?}", user.login);
    Ok(())
}
