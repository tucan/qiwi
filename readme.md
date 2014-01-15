# QIWI

Easy and lightweight client for QIWI payment system.

## Features

This library is THE FIRST open source client for QIWI.

## API

### Class Client

#### ::SERVER_NAME

- `String` Default `w.qiwi.com`

Default server name or IP address for connections to.

#### ::SERVER_PORT

- `Number` Default `443`

Default server port for connections to.

#### ::REQUEST_CHARSET

- `String` Default `utf-8`

Description will be added.

#### ::CIPHER_IV

- `Buffer` Default `new Buffer([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])`

Default cipher initialization vector for AES.

#### ::constructor()

#### .setExtra(name, value)

- `name` String
- `value` Number | String | Boolean | null

#### .removeExtra(name)

- `name` String

#### .setSession(session)

- `session` Object

#### .removeSession()

#### .createSession(publicKey, callback)

- `publicKey` Buffer | String
- `callback` Function | null

#### .openSession(publicKey, callback)

- `publicKey` Buffer | String
- `callback` Function | null
