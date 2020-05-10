# osx-keychain [![](https://travis-ci.org/matthewhadley/osx-keychain.svg)](https://travis-ci.org/matthewhadley/osx-keychain)

Get, Set and Delete values in the osx keychain.

## Install

```
[sudo] npm i -g osx-keychain
```

## Usage

```
keychain -g <service> [username|$USER]          # get a value
keychain -s <service> <value> [username|$USER]  # set a value
keychain -d <service> [username|$USER]          # delete a value
```
