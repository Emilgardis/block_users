Block users | 
============================================

Block users on twitch using the Twitch API. Removes follow and blocks interaction. Can parse single users, one user and from a file. Can interpret user ids 

## Guide

Use [Follower list viewer by CommanderRoot](https://twitch-tools.rootonline.de/followerlist_viewer.php) to filter accounts.
(ps, you can also use their [follow remover](https://twitch-tools.rootonline.de/follower_remover.php), which is probably easier to use for some, it has built-in filters 🙂)

Save the filtered results as a file.

Generate a token with [Twitch Token Generator](https://twitchtokengenerator.com/?scope=user:read:blocked_users+user:manage:blocked_users&auth=auth_stay) (needs to have scopes `user:read:blocked_users` and `user:manage:blocked_users`)

[Download](https://github.com/Emilgardis/block_users/releases/latest) the application, and put the executable in the same folder as the file containing users to block.

```sh
cd <path to folder with executable and block list>
./block_users --access-token <token> --skip-comma --file <file> 
```

```text
USAGE:
    block-users.exe [FLAGS] [OPTIONS]

FLAGS:
        --check-first    Always check previously blocked users before sending blocks
    -h, --help           Print help information
        --skip-comma     Skip content after first comma in a line, ignoring that data
        --unblock        Unblock users instead of blocking
    -V, --version        Print version information

OPTIONS:
        --access-token <ACCESS_TOKEN>
            OAuth2 Access token [env: ACCESS_TOKEN]

        --channel-login <CHANNEL_LOGIN>
            Name of channel to get token for [env: CHANNEL_LOGIN]

        --file <FILE>
            File to read users from

        --oauth2-service-key <OAUTH2_SERVICE_KEY>
            Bearer key for authorizing on the OAuth2 service url [env: OAUTH2_SERVICE_KEY]

        --oauth2-service-pointer <OAUTH2_SERVICE_POINTER>
            Grab token by pointer. See https://tools.ietf.org/html/rfc6901 [env:
            OAUTH2_SERVICE_POINTER]

        --oauth2-service-url <OAUTH2_SERVICE_URL>
            URL to service that provides OAuth2 token. Called on start, can have {login} in url to
            replace with [channel_login] [env: OAUTH2_SERVICE_URL]

        --users <USERS>...
            Users to block
```

<h5> License </h5>

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>

