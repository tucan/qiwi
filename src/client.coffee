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
	# Default connection parameters

	@SERVER_NAME: 'w.qiwi.com'
	@SERVER_PORT: 443

	#

	@REQUEST_CHARSET: 'utf-8'

	# Cipher parameters for the protocol

	CIPHER_NAME = 'aes-256-cbc'
	CIPHER_IV = new Buffer([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
	CIPHER_KEY_LENGTH = 32

	# Magic values of the protocol

	REQUEST_PREFIX = 'v3.qiwi-'
	RESPONSE_MARKER = 'B64\n'

	# Object constructor

	constructor: () ->
		@_host = @constructor.SERVER_NAME
		@_port = @constructor.SERVER_PORT

		@_charset = @constructor.REQUEST_CHARSET

		@_extra = Object.create(null)

		@_session = null
		@_token = null

	#

	_encryptKey = (publicKey, nonce, aesKey) ->
		blob = new Buffer(2 + nonce.length + aesKey.length)

		blob[0] = nonce.length
		nonce.copy(blob, 1)

		blob[1 + nonce.length] = aesKey.length
		aesKey.copy(blob, 1 + nonce.length + 1)

		encodedKey = publicKey.encrypt(blob, null, 'base64', RSA.RSA_PKCS1_PADDING)

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

		options =
			host: @_host, port: @_port
			method: 'POST', path: path
			headers: headers

		options

	# Generate onResponse handler for provided callback

	_responseHandler: (callback) -> (response) =>
		# Array for arriving chunks

		chunks = []

		# Assign necessary event handlers

		response.on('readable', () ->
			chunks.push(response.read())

			undefined
		)

		response.on('end', () =>
			body = Buffer.concat(chunks)

			text = Iconv.decode(body, 'utf-8')

			# Decrypt text (if it was encrypted of course)

			if text[0..3] is RESPONSE_MARKER
				text = Iconv.decode(@_decryptBody(text[4..]), 'utf-8')

			output = XML.parse(text)

			callback(null, output.response)

			undefined
		)

		undefined

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

			undefined
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

				undefined
			)

			undefined
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
		envelope.request[key] = value for key, value of input	# BUG: extra can be overwriten

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

			undefined
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

		@

	#

	accountInfo: (callback) ->
		fullInput =
			'terminal-id': @_terminalId
			extra: $: (name: 'token'), $text: @_token

		@invokeMethod('ping', fullInput, callback)

	#

	favouriteList: (callback) ->
		input =
			'terminal-id': @_terminalId
			extra: $: (name: 'token'), $text: @_token

		@invokeMethod('get-ab', input, callback)

	#

	operationReport: (input, callback) ->
		data =
			'terminal-id': @_token.owner
			extra: $: (name: 'token'), $text: @_token.value

			period: 'today'
			full: 1

			period: 'custom'
			'from-date': '25.12.2013'
			'to-date': '08.01.2014'

		@invokeMethod('get-payments-report', data, callback)

	#

	makePayment: (input, callback) ->
		input =
			'terminal-id': @_token.owner
			extra: $: (name: 'token'), $text: @_token.value
			auth: payment: input

		@invokeMethod('pay', input, callback)

	#

	checkPayment: (input, callback) ->
		fullInput =
			'terminal-id': @_terminalId
			extra: $: (name: 'token'), $text: @_token

			check: payment: input

		@invokeMethod('pay', fullInput, callback)

# Exported objects

module.exports = Client
