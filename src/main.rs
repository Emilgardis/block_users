#![feature(option_result_contains)]

use std::io::BufRead;

use anyhow::Context;
use clap::{ArgGroup, Parser};
use twitch_api::{
    helix::{
        make_stream, moderation,
        users::{block_user, get_user_block_list, get_users},
    },
    twitch_oauth2::{self, TwitchToken, UserToken},
    types::{self, UserName},
};

#[derive(Debug, clap::Parser)]
#[clap(about, version,
    group = ArgGroup::new("token").multiple(false).required(false),
    group = ArgGroup::new("service").multiple(true),
)]
pub struct Opts {
    /// OAuth2 Access token.
    #[clap(long, env, group = "token",
        validator = is_token, required_unless_present = "service",
    )]
    pub access_token: Option<Secret>,
    /// Name of channel to get token for.
    #[clap(long, env, group = "service", required_unless_present = "token")]
    pub channel_login: Option<String>,
    /// URL to service that provides OAuth2 token. Called on start, can have {login} in url to replace with [channel_login].
    #[clap(long, env, group = "token",
        validator = url::Url::parse,
        required_unless_present = "token"
    )]
    pub oauth2_service_url: Option<String>,
    /// Bearer key for authorizing on the OAuth2 service url.
    #[clap(long, env, group = "service")]
    pub oauth2_service_key: Option<Secret>,
    /// Grab token by pointer. See https://tools.ietf.org/html/rfc6901
    #[clap(
        long,
        env,
        group = "service",
        default_value_if("oauth2-service-url", None, Some("/access_token"))
    )]
    pub oauth2_service_pointer: Option<String>,
    #[clap(subcommand)]
    pub subcommand: Subcommand,
}

#[derive(clap::Subcommand, Debug)]
pub enum Subcommand {
    Block(Block),
    Followers(Followers),
    Ban(Ban),
}

#[derive(clap::Args, Debug)]
pub struct Ban {
    /// File to read users from
    #[clap(long, required_unless_present = "users", conflicts_with = "users")]
    pub file: Option<std::path::PathBuf>,
    /// Skip content after first comma in a line, ignoring that data
    #[clap(long)]
    pub skip_comma: bool,
    /// Always check previously baned users before sending bans.
    #[clap(long)]
    pub check_first: bool,
    /// Unban users instead of banning.
    #[clap(long)]
    pub unban: bool,
    /// Moderator that will ban
    #[clap(long)]
    pub moderator: String,
    /// broadcasters channel to ban in
    #[clap(long)]
    pub broadcaster: String,
    /// Users to ban.
    #[clap(
        long,
        required_unless_present = "file",
        conflicts_with = "file",
        multiple_values = true
    )]
    pub users: Option<Vec<String>>,
}

#[derive(clap::Args, Debug)]
pub struct Block {
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
}

#[derive(clap::Args, Debug)]
pub struct Followers {
    #[clap(long, short)]
    pub last: usize,
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
    client: &'a impl twitch_oauth2::client::Client,
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
async fn main() -> anyhow::Result<()> {
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

    match &opts.subcommand {
        Subcommand::Block(block) => run_block(&opts, &block).await,
        Subcommand::Followers(followers) => run_followers(&opts, &followers).await,
        Subcommand::Ban(ban) => run_ban(&opts, &ban).await,
    }
}

pub async fn run_ban(opts: &Opts, ban: &Ban) -> anyhow::Result<()> {
    let reqwest: reqwest::Client = twitch_api::client::ClientDefault::default_client_with_name(
        Some("emilgardis/block_user".parse()?),
    )
    .with_context(|| "could not create reqwest client")?;
    let client: twitch_api::HelixClient<reqwest::Client> =
        twitch_api::HelixClient::with_client(reqwest);
    let token = get_access_token(&client.clone_client(), opts).await?;
    let token = std::sync::Arc::new(token);

    let moderator = client
        .get_user_from_login(&*ban.moderator, &*token)
        .await?
        .ok_or_else(|| anyhow::anyhow!("couldn't get moderator"))?;
    let broadcaster = client
        .get_user_from_login(&*ban.broadcaster, &*token)
        .await?
        .ok_or_else(|| anyhow::anyhow!("couldn't get moderator"))?;

    let banning: Vec<types::Nickname> = match (&ban.file, &ban.users) {
        (Some(file), None) if !ban.skip_comma => std::fs::read(&file)?
            .lines()
            .map(|r| r.map(types::Nickname::from))
            .collect::<Result<_, _>>()?,
        (Some(file), None) if ban.skip_comma => std::fs::read(&file)?
            .lines()
            .map(|r| r.map(|s| types::Nickname::from(s.split_once(',').unwrap_or_default().0)))
            .collect::<Result<_, _>>()?,
        (None, Some(users)) => users.iter().map(|s| s.as_str().into()).collect(),
        _ => anyhow::bail!("can't specify a user and a file at the same time"),
    };
    for user in banning {
        if ban.unban {
            unban_user(&client, &user, &moderator.id, &broadcaster.id, &token).await?;
        } else {
            ban_user(&client, &user, &moderator.id, &broadcaster.id, &token).await?;
        }
    }
    Ok(())
}
pub async fn run_block(opts: &Opts, block: &Block) -> anyhow::Result<()> {
    use futures::{StreamExt, TryStreamExt};
    let reqwest: reqwest::Client = twitch_api::client::ClientDefault::default_client_with_name(
        Some("emilgardis/block_user".parse()?),
    )
    .with_context(|| "could not create reqwest client")?;
    let client: twitch_api::HelixClient<reqwest::Client> =
        twitch_api::HelixClient::with_client(reqwest);
    let token = get_access_token(&client.clone_client(), opts).await?;
    let token = std::sync::Arc::new(token);

    let list: Vec<types::Nickname> = match (&block.file, &block.users) {
        (Some(file), None) if !block.skip_comma => std::fs::read(&file)?
            .lines()
            .map(|r| r.map(types::Nickname::from))
            .collect::<Result<_, _>>()?,
        (Some(file), None) if block.skip_comma => std::fs::read(&file)?
            .lines()
            .map(|r| r.map(|s| types::Nickname::from(s.split_once(',').unwrap_or_default().0)))
            .collect::<Result<_, _>>()?,
        (None, Some(users)) => users.iter().map(|s| s.as_str().into()).collect(),
        _ => anyhow::bail!("can't specify a user and a file at the same time"),
    };

    if block.unblock {
        for user in list {
            unblock_user(&client, &user, &token).await?
        }
        return Ok(());
    }

    let mut blocking = vec![];

    for user in list {
        blocking.push(match client.get_user_from_login(&user, &*token).await? {
            Some(u) => u,
            None if user.as_str().as_bytes().iter().all(|b| b.is_ascii_digit()) => {
                match client.get_user_from_id(user.as_str(), &*token).await? {
                    Some(u) => u,
                    None => {
                        tracing::info!(user=%user, "user does not exist");
                        continue;
                    }
                }
            }
            _ => {
                tracing::info!(user=%user, "user does not exist");
                continue;
            }
        });
    }

    let blocked_req =
        get_user_block_list::GetUserBlockListRequest::broadcaster_id(&token.user_id);
    let previously_blocked = std::sync::Arc::new(tokio::sync::Mutex::new(vec![]));
    let mut first_run = true;
    loop {
        let previously_blocked = previously_blocked.clone();
        let mut blocked: Vec<get_user_block_list::UserBlock> = {
            let pb_lock = previously_blocked.lock().await;
            pb_lock.clone()
        };

        if !first_run || block.check_first {
            // We check blocks one time again before calling api, since we might have hit only suspened/non existing accounts
            if !blocking
                .iter()
                .any(|s| !blocked.iter().any(|b| b.user_id == s.id))
            {
                tracing::info!("nothing more to block");
                break;
            }
            tracing::info!("checking blocked users");
            blocked.extend(
                make_stream(blocked_req.clone(), &*token, &client, |s| {
                    s.into_iter().collect()
                })
                //.try_take_while(|n| futures::future::ready(Ok(!last.as_deref().contains(&n))))
                .try_collect::<Vec<_>>()
                .await?,
            );
        }
        let to_block = blocking
            .clone()
            .into_iter()
            .filter(|s| !blocked.iter().any(|b| b.user_id == s.id))
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
            .try_for_each_concurrent(4, |n| {
                let client = client.clone();
                let token = token.clone();
                async move { block_user(&client.clone(), &n, &token.clone()).await }
            })
            .await?;
    }

    Ok(())
}

pub async fn run_followers(opts: &Opts, followers: &Followers) -> anyhow::Result<()> {
    use futures::{StreamExt, TryStreamExt};
    let reqwest: reqwest::Client = twitch_api::client::ClientDefault::default_client_with_name(
        Some("emilgardis/block_user".parse()?),
    )
    .with_context(|| "could not create reqwest client")?;
    let client: twitch_api::HelixClient<reqwest::Client> =
        twitch_api::HelixClient::with_client(reqwest);
    let token = get_access_token(&client.clone_client(), opts).await?;
    let token = std::sync::Arc::new(token);

    let followers: Vec<_> = client
        .get_follow_relationships(token.user_id().map(Into::into), None, &*token)
        .take(followers.last)
        .try_collect()
        .await?;
    println!(
        "{}",
        serde_json::to_string(&followers)?
            .replace("{", "\n{")
            .replace("}]", "}\n]")
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exists {
    Yes,
    No(UserName),
}

pub async fn ban_user<'c, C: twitch_api::client::Client + Sync + 'c>(
    client: &'c twitch_api::HelixClient<'c, C>,
    user_login: &types::UserNameRef,
    moderator_id: &types::UserIdRef,
    broadcaster_id: &types::UserIdRef,
    token: &twitch_oauth2::UserToken,
) -> anyhow::Result<Exists> {
    let user = match client
        .get_user_from_login(user_login, token)
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
    let req = moderation::BanUserRequest::new(broadcaster_id, moderator_id);
    let body = moderation::BanUserBody::new(user.id, "Follow Bot".to_owned(), None);

    match client.req_post(req, body, token).await {
        Ok(_) => (),
        Err(twitch_api::helix::ClientRequestError::HelixRequestPostError(
            twitch_api::helix::HelixRequestPostError::Error {
                status, message, ..
            },
        )) if message == "The user specified in the user_id field is already banned."
            && status == http::StatusCode::BAD_REQUEST =>
        {
            ()
        }
        Err(e) => Err(e)?,
    }
    tracing::info!("banned {:?}", user.login);
    Ok(Exists::Yes)
}

pub async fn unban_user<'c, C: twitch_api::client::Client + Sync + 'c>(
    _client: &'c twitch_api::HelixClient<'c, C>,
    _user_login: &types::UserNameRef,
    _moderator_id: &types::UserIdRef,
    _broadcaster_id: &types::UserIdRef,
    _token: &twitch_oauth2::UserToken,
) -> anyhow::Result<Exists> {
    todo!()
}

pub async fn block_user<'c, C: twitch_api::client::Client + Sync + 'c>(
    client: &'c twitch_api::HelixClient<'c, C>,
    user: &get_users::User,
    token: &twitch_oauth2::UserToken,
) -> anyhow::Result<()> {
    let req = block_user::BlockUserRequest::block_user(&*user.id)
        .reason(block_user::Reason::Other)
        .source_context(block_user::SourceContext::Chat);

    let _ = client.req_put(req, <_>::default(), token).await?;
    tracing::info!("blocked {:?}", user.login);
    Ok(())
}

pub async fn unblock_user<'c, C: twitch_api::client::Client + Sync + 'c>(
    client: &'c twitch_api::HelixClient<'c, C>,
    user_login: &types::UserNameRef,
    token: &twitch_oauth2::UserToken,
) -> anyhow::Result<()> {
    use twitch_api::helix::users::unblock_user;
    let user = client
        .get_user_from_login(user_login, token)
        .await?
        .unwrap();
    let req = unblock_user::UnblockUserRequest::unblock_user(user.id);

    let _ = client.req_delete(req, token).await?;
    tracing::info!("unblocked {:?}", user.login);
    Ok(())
}
