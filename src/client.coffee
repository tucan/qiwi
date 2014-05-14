# Copyright Vladimir Andreev

# Required modules

HTTPS = require('https')
Crypto = require('crypto')
RSA = require('ursa')

Iconv = require('iconv-lite')
XML = require('nice-xml')
QS = require('qs')

# QIWI client

class Client
	# Connection default parameters

	@SERVER_NAME: 'w.qiwi.com'
	@SERVER_PORT: 443

	# Request and response default parameters

	@REQUEST_CHARSET: 'utf-8'
	@RESPONSE_MAX_SIZE: 1024 * 1024 	# 1M

	# Cipher parameters

	CIPHER_NAME = 'aes-256-cbc'
	CIPHER_IV = new Buffer([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
	CIPHER_KEY_LENGTH = 32

	# Magic values of the protocol

	REQUEST_PREFIX = 'v3.qiwi-'
	RESPONSE_MARKER = 'B64\n'

	# Object constructor

	constructor: (options) ->
		@_host = @constructor.SERVER_NAME
		@_port = @constructor.SERVER_PORT

		@_charset = @constructor.REQUEST_CHARSET

		@_headers = Object.create(null)
		@_extra = Object.create(null)

		@_session = null
		@_token = null
		@_terminalId = null

	#

	_encryptKey = (publicKey, nonce, aesKey) ->
		blob = new Buffer(2 + nonce.length + aesKey.length)

		blob[0] = nonce.length
		nonce.copy(blob, 1)

		blob[1 + nonce.length] = aesKey.length
		aesKey.copy(blob, 1 + nonce.length + 1)

		publicKey.encrypt(blob, null, 'base64', RSA.RSA_PKCS1_PADDING)

	# Encrypts request body and returns string containing encrypted data

	_encryptBody: (data) ->
		cipher = Crypto.createCipheriv(CIPHER_NAME, @_session.key, CIPHER_IV)

		cipher.end(data)
		blob = cipher.read()

		REQUEST_PREFIX + @_session.id + '\n' + blob.toString('base64')

	#

	_decryptBody: (text) ->
		decipher = Crypto.createDecipheriv(CIPHER_NAME, @_session.key, CIPHER_IV)

		decipher.end(text, 'base64')

		decipher.read()

	# Generate request options based on provided parameters
 
	_requestOptions: (endpoint, body) ->
		path = '/xml/xmlutf_' + endpoint + '.jsp'

		headers =
			'Content-Type': 'application/x-www-form-urlencoded; charset=' + @_charset
			'Content-Length': body.length

		# Merge const headers and request specific headers

		fullHeaders = Object.create(null)

		fullHeaders[key] = value for key, value of @_headers
		fullHeaders[key] = value for key, value of headers

		options =
			host: @_host, port: @_port
			method: 'POST', path: path
			headers: fullHeaders

		options

	# Generate onResponse handler for provided callback

	_responseHandler: (callback) -> (response) =>
		# Array for arriving chunks

		chunks = []

		# Assign necessary event handlers

		response.on('readable', () ->
			chunks.push(response.read())

			return
		)

		response.on('end', () =>
			body = Buffer.concat(chunks)

			text = Iconv.decode(body, 'utf-8')

			# Decrypt text (if it was encrypted of course)

			if text[0..3] is RESPONSE_MARKER
				text = Iconv.decode(@_decryptBody(text[4..]), 'utf-8')

			output = XML.parse(text)

			callback(null, output.response)

			return
		)

		return

	#

	setHeader: (name, value) ->
		@_headers[name] = value

		@

	#

	removeHeader: (name) ->
		delete @_headers[name]

		@

	# Sends init request to the server

	sendInit: (input, callback) ->
		# Make serialization and encode derived text

		blob = Iconv.encode(QS.stringify(input), @_charset)

		# Create request using generated options

		request = HTTPS.request(@_requestOptions('newcrypt_init_session', blob))

		# Assign necessary event handlers

		request.on('response', @_responseHandler(callback))

		request.on('error', (error) ->
			callback?(error)

			return
		)

		# Write body and finish request

		request.end(blob)

		@

	# Creates new session using provided public key

	createSession: (publicKey, callback) ->
		publicKey = RSA.createPublicKey(publicKey)

		# Phase 1 - receive server nonce

		@sendInit(command: 'init_start', (error, output) =>
			# Extract necessary data from server response

			sessionId = output.session_id
			serverNonce = new Buffer(output.init_hs, 'base64')

			# Create AES key and encrypt it using public RSA key

			aesKey = Crypto.randomBytes(CIPHER_KEY_LENGTH)
			encryptedKey = _encryptKey(publicKey, serverNonce, aesKey)

			# Phase 2 - send our encrypted key to the server

			input = command: 'init_get_key', session_id: sessionId, key_v: 2, key_hs: encryptedKey

			@sendInit(input, (error) =>
				unless error?
					session = id: sessionId, key: aesKey
					callback?(null, session)
				else
					callback?(error)

				return
			)

			return
		)
		
		@

	# Makes provided session current

	setSession: (session) ->
		@_session = session

		@

	# Removes previously stored session data

	removeSession: () ->
		@_session = null

		@

	# Invokes pointed method on the remote side

	invokeMethod: (name, input, callback) ->
		# Form request data based on provided input

		envelope = request: 'request-type': name

		extra = []
		extra.push($: (name: key), $text: value) for key, value of @_extra

		envelope.request.extra = extra if extra.length

		for key, value of input
			item = envelope.request[key]

			unless item?
				envelope.request[key] = value
			else if Array.isArray(item)
				item.push(value)
			else
				envelope.request[key] = [item, value]

		# Make serialization and encode derived text

		blob = Iconv.encode(XML.stringify(envelope), @_charset)

		# Encrypt plain body and encode derived cipher-text

		blob = Iconv.encode(@_encryptBody(blob), @_charset)

		# Create request using generated options

		request = HTTPS.request(@_requestOptions('newcrypt', blob))

		# Assign necessary event handlers

		request.on('response', @_responseHandler(callback))

		request.on('error', (error) ->
			callback?(error)

			return
		)

		# Write body and finish request

		request.end(blob)

		@

	# Sets extra field to be sent to the server

	setExtra: (name, value) ->
		@_extra[name] = value

		@

	# Removes extra field with pointed name

	removeExtra: (name) ->
		delete @_extra[name]

		@

	#

	receiveToken: (input, callback) ->
		fullInput = 'client-id': 'android', 'auth-version': '2.0'
		fullInput[key] = value for key, value of input when value isnt undefined

		@invokeMethod('oauth-token', fullInput, callback)

	#

	setAccess: (token, terminalId) ->
		@_token = token
		@_terminalId = terminalId

		@

	#

	removeAccess: () ->
		@_token = null
		@_terminalId = null

		@

	#

	accountInfo: (callback) ->
		fullInput =
			'terminal-id': @_terminalId
			extra: $: (name: 'token'), $text: @_token

		@invokeMethod('ping', fullInput, callback)

	#

	chargeList: (input, callback) ->
		fullInput =
			'terminal-id': @_terminalId
			extra: $: (name: 'token'), $text: @_token

			check: payment: input

		@invokeMethod('pay', fullInput, callback)

	#

	operationReport: (input, callback) ->
		fullInput =
			'terminal-id': @_terminalId
			extra: $: (name: 'token'), $text: @_token

		fullInput[key] = value for key, value of input when value isnt undefined

		@invokeMethod('get-payments-report', fullInput, callback)

	#

	makePayment: (input, callback) ->
		fullInput =
			'terminal-id': @_terminalId
			extra: $: (name: 'token'), $text: @_token

			auth: payment: input

		@invokeMethod('pay', fullInput, callback)

# Exported objects

module.exports = Client
