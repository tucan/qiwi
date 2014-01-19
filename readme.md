# QIWI

Easy and lightweight client for QIWI payment system.

## Features

This library is THE FIRST open source client for QIWI.

Currently this library is in development, so not all may work as expected.

## Installation

```
$ npm install qiwi
```

## Usage

```coffeescript
QIWI = require('qiwi')

client = new QIWI.Client()

client.createSession((error, session) ->
	unless error?
		client.setSession(session)

		client.accountInfo((error) ->
			unless error?
				console.log('Your account details:')
				console.log(info)
			else
				console.log('Something went wrong:')
				console.log(error)

			undefined
		)
	else
		console.log('Unable to open session')
		console.log(error)

	undefined
)
```

## API

### Class Client

This class represents client for QIWI.

#### ::SERVER_NAME

- `String` Default `w.qiwi.com`

Default server name or IP address for connections to.

#### ::SERVER_PORT

- `Number` Default `443`

Default server port for connections to.

#### ::REQUEST_CHARSET

- `String` Default `utf-8`

Charset which will be used by client while sending requests.

#### ::constructor(options)

Description will be added.

#### .setHeader(name, value)
- `name` String
- `value` String

Sets HTTP header with pointed name and value for subsequent requests.

#### .removeHeader(name)
- `name` String

Removes header with pointed name.

#### .createSession(publicKey, callback)

- `publicKey` Buffer | String
- `callback` Function | null

Establishes new encrypted sesssion.

You need to specify `publicKey` which currently is the same for all clients and can be loaded from `./qiwi.pub`. This function generates symmetric key for AES-256, encrypts it using `publicKey` and sends to the server. Session object will be passed to `callback`. In order to make other calls you should install session into client using `setSession`.

The schema described above is similar to SSL in general states.

#### .setSession(session)

- `session` Object

Sets session object for subsequent requests.

#### .removeSession()

Removes stored session from client.

#### .setExtra(name, value)

- `name` String
- `value` Number | String | Boolean | null

Sets extra field with `name` and `value` to be sent to the server on each request.

#### .removeExtra(name)

- `name` String

Removes field identified by `name`.

#### .setAuth(token, terminalId)

- `token` String
- `terminalId` String | undefined

Sets `token` and `terminalId` for subsequent requests.

#### .removeAuth()

Removes previously stored token and terminal ID.
