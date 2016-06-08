# envchain - set environment variables with OS X keychain or D-Bus secret service

## What?

Secrets for common computing environments, such as `AWS_SECRET_ACCESS_KEY`, are
set with environment variables.

A common practice is to set them in shell's intialization files such as `.bashrc` and `.zshrc`.

Putting these secrets on disk in this way is a grave risk.

`envchain` allows you to secure credential environment variables to your secure vault, and set to environment variables only when you called explicitly.

Currently, `envchain` supports OS X keychain and D-Bus secret service (gnome-keyring) as a vault.

Don't give any credentials implicitly!

## Requirement (OS X)

- OS X
  - Confirmed to work on OS X 10.9 (Mavericks), 10.10 (Yosemite), and 10.11 (El Capitan)
  - OS X 10.7 (Lion) or later is required, but not confirmed

## Requirement (Linux)

- readline
- libsecret
- D-Bus Secret Service
    - GNOME keyring is a common (and only?) implementation for it

## Installation

### From Source

```
$ make

$ sudo make install
(or)
$ cp ./envchain ~/bin/
```

### Homebrew (OS X)

```
brew install envchain
```

## Usage

### Define variables

```
$ envchain --set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
aws.AWS_ACCESS_KEY_ID: my-access-key
aws.AWS_SECRET_ACCESS_KEY: secret
```

You can separate environment variables via namespaces:

```
$ envchain --set hubot HUBOT_HIPCHAT_PASSWORD
hubot.HUBOT_HIPCHAT_PASSWORD: xxxx
```

These will appear as application passwords with `envchain-NAMESPACE`
in Keychain.

### Execute commands with defined variables

```
$ env | grep AWS_ || echo "No AWS_ env vars"
No AWS_ env vars
$ envchain aws env | grep AWS_
AWS_ACCESS_KEY_ID=my-access-key
AWS_SECRET_ACCESS_KEY=secret
$ envchain aws s3cmd blah blah blah
⋮
```

```
$ envchain hubot env | grep AWS_ || echo "No AWS_ env vars for hubot"
No AWS_ env vars for hubot
$ envchain hubot env | grep HUBOT_
HUBOT_HIPCHAT_PASSWORD: xxxx
```

### More options

#### `--noecho`

Do not echo user input
```
$ envchain --set --noecho foo BAR
foo.BAR (noecho):
```
#### `--require-passphrase`

Always ask for keychain passphrase
```
$ envchain --set --require-passphrase name
```

#### `--no-require-passphrase`

Do not ask for keychain passphrase
```
$ envchain --set --no-require-passphrase name
```

### Screenshot

![](http://img.sorah.jp/20140519_060147_dqwbh_20140519_060144_s1zku_Keychain_Access.png)

## Author

Shota Fukumori (sora\_h) <her@sorah.jp>

## License

MIT License
