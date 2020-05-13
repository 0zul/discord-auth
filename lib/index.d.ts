declare module 'discord-auth' {
  export default class Strategy {
    /**
     * `Strategy` constructor.
     *
     * The Discord authentication strategy authenticates requests by delegating to
     * Discord via the OAuth2.0 protocol
     *
     * Applications must supply a `verify` callback which accepts an `accessToken`,
     * `refreshToken` and service-specific `profile`, and then calls the `cb`
     * callback supplying a `user`, which should be set to `false` if the
     * credentials are not valid. If an exception occured, `err` should be set.
     *
     * Options:
     *   - `clientID`       OAuth ID to discord
     *   - `clientSecret`   OAuth Secret to verify client to discord
     *   - `callbackURL`    URL that discord will redirect to after auth
     *   - `scope`          Array of permission scopes to request
     *                      Check the official documentation for valid scopes to pass as an array.
     */
    constructor(options: {
      clientID: string,
      clientSecret: string,
      callbackURL: string,
      scope?: string | string[];
    }, verify: (accessToken: string, refreshToken: string, profile: string, cb: (err: Error, user?: object) => void) => void)
  }
}
