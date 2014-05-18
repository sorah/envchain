# envchain - inject environment variables by OS X keychain

## What?

Are you writing credentials like `export AWS_SECRET_ACCESS_KEY=XXX` in `~/.bashrc` or `zshrc`?
If you're doing so, __that's a risk.__ In such environment, malicious scripts can get credentials via environment variable.
Easy to steal!

`envchain` allows you to secure credential environment variables using OS X keychain, and set to environment variables only when you called explicitly.

Don't give any credentials implicitly!

## Requirement

- OS X
  - At least I confirmed to work on OS X 10.9 (Mavericks)
  - (I guess) OS X 10.7 (Lion) or later is required

## Installation

```
$ make

$ sudo make install
(or)
$ cp ./envchain ~/bin/
```

## Usage

### Define variables

```
$ envchain --set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
aws.AWS_ACCESS_KEY_ID: my-access-key
aws.AWS_SECRET_ACCESS_KEY: secret

(supporting multiple namespaces)
$ envchain --set hubot HUBOT_HIPCHAT_PASSWORD
hubot.HUBOT_HIPCHAT_PASSWORD: xxxx
```

They'll appear on your keychain.

![](http://img.sorah.jp/20140519_060147_dqwbh_20140519_060144_s1zku_Keychain_Access.png)

### Execute with defined variables

```
$ envchain aws env | grep AWS_
AWS_ACCESS_KEY_ID=my-access-key
AWS_SECRET_ACCESS_KEY=secret
```

```
$ envchain aws hubot | grep AWS_
$ envchain aws hubot | grep HUBOT_
HUBOT_HIPCHAT_PASSWORD: xxxx
```

### More options

```
- prompting with noecho
$ envchain --set --noecho foo BAR
foo.BAR (noecho): 

- Always ask keychain password
$ envchain --set --require-passphrase name

- Disable ditto
$ envchain --set --no-require-passphrase name
```

## Author

Shota Fukumori (sora\_h) <her@sorah.jp>

## License

MIT License
