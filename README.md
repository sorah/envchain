# envchain - set environment variables with macOS keychain or D-Bus secret service

## What?

Secrets for common computing environments, such as `AWS_SECRET_ACCESS_KEY`, are
set with environment variables.

A common practice is to set them in shell's intialization files such as `.bashrc` and `.zshrc`.

Putting these secrets on disk in this way is a grave risk.

`envchain` allows you to secure credential environment variables to your secure vault, and set to environment variables only when you called explicitly.

Currently, `envchain` supports macOS keychain and D-Bus secret service (gnome-keyring) as a vault.

Don't give any credentials implicitly!

## Requirement (macOS)

- macOS
  - Confirmed to work on OS X 10.11 (El Capitan), macOS 10.12 (Sierra).
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

### Saving variables

Environment variables are set within a specified _namespace._ You can set variables in a single command:

```
envchain --set NAMESPACE ENV [ENV ..]
```

You will be prompted to enter the values for each variable.
For example, we can set two variables... `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` here, within a namespace called `aws`:

```
$ envchain --set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
aws.AWS_ACCESS_KEY_ID: my-access-key
aws.AWS_SECRET_ACCESS_KEY: secret
```

Here we define a single new variable within a different namespace:

```
$ envchain --set hubot HUBOT_HIPCHAT_PASSWORD
hubot.HUBOT_HIPCHAT_PASSWORD: xxxx
```

These will all appear as application passwords with `envchain-NAMESPACE` in the data store (Keychain in macOS, gnome-keyring in common Linux distros).

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

#### OS X Keychain

![](http://img.sorah.jp/20140519_060147_dqwbh_20140519_060144_s1zku_Keychain_Access.png)

#### Seahorse (gnome-keyring)

![](https://img.sorah.jp/2016-06-08_19-46-10_ff9c444.png)

## Author

- Sorah Fukumori <her@sorah.jp>
- eagletmt

## License

MIT License
