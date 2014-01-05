# Copyright Vladimir Andreev

# Required modules

HTTPS = require('https')
Crypto = require('crypto')
RSA = require('ursa')
Iconv = require('iconv-lite')
QueryString = require('qs')

# QIWI client

class Client
	# Default connection parameters

	@SERVER_NAME: 'w.qiwi.com'
	@SERVER_PORT: 443

	#

	@REQUEST_CHARSET: 'utf-8'

	# Default IV for AES

	@CIPHER_IV: new Buffer([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

	# Object constructor

	constructor: () ->
		@_host = @constructor.SERVER_NAME
		@_port = @constructor.SERVER_PORT

		@_sessionId = null
		@_key = null

		@_charset = 'utf-8'

	#

	_encrypt: (data) ->
		cipher = Crypto.createCipheriv('aes-256-cbc', @_key, @constructor.IV)
		encryptedText = cipher.update(data).toString('hex')
		encryptedText += cipher.final().toString('hex')

		'v3.qiwi-' + @_sessionId + '\n' + new Buffer(encryptedText, 'hex').toString('base64')

	#

	_decrypt: (data) ->
		decipher = Crypto.createDecipheriv('aes-256-cbc', @_key, @constructor.IV)
		decryptedText = decipher.update(data, 'base64').toString('utf8')
		decryptedText += decipher.final().toString('utf8')

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

	_responseHandler: (callback) -> (response) ->
		# Array for arriving chunks

		chunks = []

		# Assign necessary event handlers

		response.on('readable', () ->
			chunks.push(response.read())

			undefined
		)

		response.on('end', () ->
			body = Buffer.concat(chunks)

			callback(null, body.toString('utf-8'))

			undefined
		)

		undefined

	# Sets extra field to be sent to the server

	setExtra: (name, value) ->
		@_extra[name] = value

		@

	# Removes extra field with pointed name

	removeExtra: (name) ->
		delete @_extra[name]

		@

	#

	sendRequest: (endpoint, data, callback) ->
		# Make serialization and derived text encoding

		body = Iconv.encode(QueryString.stringify(data), @_charset)

		# Create request using generated options

		request = HTTPS.request(@_requestOptions(endpoint, body))

		# Assign necessary event handlers

		request.on('response', @_responseHandler(callback))

		request.on('error', (error) ->
			callback?(error)

			undefined
		)

		# Write body and finish request

		request.end(body)

		@

	#

	sendEncryptedRequest: (endpoint, data, callback) ->
		# Make serialization and derived text encoding

		encryptedText = @_encrypt(data)
		#console.log(encryptedText)

		body = Iconv.encode(encryptedText, @_charset)

		# Create request using generated options

		request = HTTPS.request(@_requestOptions(endpoint, body))

		# Assign necessary event handlers

		request.on('response', @_responseHandler(callback))

		request.on('error', (error) ->
			callback?(error)

			undefined
		)

		# Write body and finish request

		request.end(body)

		@

	# Creates new session using provided public key

	createSession: (publicKey, callback) ->
		@sendRequest('newcrypt_init_session', command: 'init_start', (error, data) =>
			# Pseudo XML parsing

			initSalt = new Buffer(data.match(/<init_hs>(.*)<\/init_hs>/)[1], 'base64')
			sessionId = data.match(/<session_id>(.*)<\/session_id>/)[1]

			aesKey = Crypto.randomBytes(32)

			blob = new Buffer(2 + initSalt.length + aesKey.length)

			blob[0] = initSalt.length
			initSalt.copy(blob, 1)

			blob[1 + initSalt.length] = aesKey.length
			aesKey.copy(blob, 1 + initSalt.length + 1)

			encodedKey = publicKey.encrypt(blob, null, 'base64', RSA.RSA_PKCS1_PADDING)

			# Sends our generated AES key to the server

			input =
				command: 'init_get_key'
				session_id: sessionId
				key_hs: encodedKey, key_v: 2

			@sendRequest('newcrypt_init_session', input, (error, data) =>
				unless error?
					session = Object.create(null)

					session.id = sessionId
					session.key = aesKey

					callback?(null, session)
				else
					callback?(error)

				undefined
			)

			undefined
		)
		
		@

	# Creates new session and makes it current

	openSession: (publicKey, callback) ->
		@createSession(publicKey, (error, session) =>
			@session = session unless error?

			callback?(error)

			undefined
		)

# Exported objects

module.exports = Client
