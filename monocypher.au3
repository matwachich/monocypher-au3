#include-once
#include <Crypt.au3>
#include <Memory.au3>

Global $__gMonocypher_hDLL = -1

; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_Startup
; Description ...:
; Syntax ........: _MC_Startup([$sDLLPath = Default])
; Parameters ....: $sDLLPath            - [optional] a string value. Default is Default.
; Return values .: None
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _MC_Startup($sDLLPath)
	If $__gMonocypher_hDLL <> -1 Then Return True
	$__gMonocypher_hDLL = DllOpen($sDLLPath)
	If $__gMonocypher_hDLL = -1 Then
		MsgBox(16, @ScriptName, "Monocypher3 DllOpen failed")
		Exit -1
	EndIf
	Return True
EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_Shutdown
; Description ...:
; Syntax ........: _MC_Shutdown()
; Parameters ....: None
; Return values .: None
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _MC_Shutdown()
	If $__gMonocypher_hDLL <> -1 Then
		DllClose($__gMonocypher_hDLL)
		$__gMonocypher_hDLL = -1
	EndIf
	Return True
EndFunc


#Region Authenticated encryption ================================================================================================
; https://monocypher.org/manual/aead

; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_Lock
; Description ...: Encrypts and authenticates a plaintext.
; Syntax ........: _MC_Lock($bPlain, $b32_Key, $b24_Nonce, Byref $b16_Mac[, $bAd = ""])
; Parameters ....: $bPlain              - Data to encrypt. If not binary, will be converted to binary using
;                                         StringToBinary($bPlain, $SB_UTF8).
;                  $b32_Key             - A 32-byte session key, shared between the sender and the recipient.
;                                         It must be secret and random.
;                  $b24_Nonce           - A 24-byte number, used only once with any given session key.
;                                         It does not need to be secret or random, but it does have to be unique.
;                                         Never use the same nonce twice with the same key.
;                  $b16_Mac             - Will be filled with the 16 bytes MAC (message authentication code), that can only be
;                                         produced by someone who knows the session key.
;                                         The MAC is intended to be sent along with the ciphertext.
;                  $bAd                 - Additional data to authenticate. It will not be encrypted. Default is no additional
;                                         data.
; Return values .: Encrypted data.
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......: If a parameter is not the right size, program will exit.
; Related .......: _MC_Unlock
; Link ..........: https://monocypher.org/manual/aead
; Example .......: No
; ===============================================================================================================================
Func _MC_Lock($bPlain, $b32_Key, $b24_Nonce, ByRef $b16_Mac, $bAd = "")
	Local $tKey = __MC_binToStruct($b32_Key, 32)
	Local $tNonce = __MC_binToStruct($b24_Nonce, 24)
	Local $tMac = DllStructCreate("byte[16]")
	Local $tAd = __MC_binToStruct($bAd)
	Local $iAdSize = @extended
	Local $tData = __MC_binToStruct($bPlain)

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_lock_aead", _
		"struct*", $tMac, _     ;       uint8_t mac[16]
		"struct*", $tData, _    ;       uint8_t *cipher_text
		"struct*", $tKey, _     ; const uint8_t key[32]
		"struct*", $tNonce, _   ; const uint8_t nonce[24]
		"struct*", $tAd, _      ; const uint8_t *ad
		"uint_ptr", $iAdSize, _ ;       size_t  ad_size
		"struct*", $tData, _    ; const uint8_t *plain_text
		"uint_ptr", @extended _ ;       size_t  text_size
	)

	$b16_Mac = DllStructGetData($tMac, 1)
	Return DllStructGetData($tData, 1)
EndFunc

;
; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_Unlock
; Description ...: Checkes message integrity and decrypt it.
; Syntax ........: _MC_Unlock($bCipher, $b32_Key, $b24_Nonce, $b16_Mac[, $bAd = ""])
; Parameters ....: $bCipher             - Data to decrypt (returned by _MC_Lock).
;                  $b32_Key             - A 32-byte session key, shared between the sender and the recipient.
;                  $b24_Nonce           - A 24-byte number, used only once with any given session key.
;                  $b16_Mac             - 16 Bytes MAC returned by _MC_Lock.
;                  $bAd                 - Additional data to authenticate (must be the same as _MC_Lock).
; Return values .: Decrypted data on succes.
;                  Empty binary string and @error = 1 if message is corrupted.
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......: If a parameter is not the right size, program will exit.
; Related .......: _MC_Lock
; Link ..........: https://monocypher.org/manual/aead
; Example .......: No
; ===============================================================================================================================
Func _MC_Unlock($bCipher, $b32_Key, $b24_Nonce, $b16_Mac, $bAd = "")
	Local $tKey = __MC_binToStruct($b32_Key, 32)
	Local $tNonce = __MC_binToStruct($b24_Nonce, 24)
	Local $tMac = __MC_binToStruct($b16_Mac, 16)
	Local $tAd = __MC_binToStruct($bAd)
	Local $iAdSize = @extended
	Local $tData = __MC_binToStruct($bCipher)

	Local $aRet = DllCall($__gMonocypher_hDLL, "int:cdecl", "crypto_unlock_aead", _
		"struct*", $tData, _    ;       uint8_t *plain_text
		"struct*", $tKey, _     ; const uint8_t key[32]
		"struct*", $tNonce, _   ; const uint8_t nonce[24]
		"struct*", $tMac, _     ; const uint8_t mac[16]
		"struct*", $tAd, _      ; const uint8_t *ad
		"uint_ptr", $iAdSize, _ ;       size_t  ad_size
		"struct*", $tData, _    ; const uint8_t *cipher_text
		"uint_ptr", @extended _ ;       size_t  text_size
	)

	If $aRet[0] = -1 Then Return SetError(1, 0, Binary(""))
	Return DllStructGetData($tData, 1)
EndFunc

#EndRegion

#Region Cryptographic hashing ===================================================================================================
; https://monocypher.org/manual/hash

; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_Blake2b
; Description ...: Calculate hash of a message using the BLAKE2b fast and cryptographically secured algorythm.
; Syntax ........: _MC_Blake2b($bMessage[, $iHashSize = 64[, $bKey = ""]])
; Parameters ....: $bMessage            - The message to hash. If not binary, will be converted to using
;                                         StringToBinary($bMessage, $SB_UTF8).
;                  $iHashSize           - [optional] Length of hash, in bytes. Must be between 1 and 64.
;                                         Anything below 32 is discouraged when using Blake2b as a general-purpose hash function;
;                                         anything below 16 is discouraged when using Blake2b as a message authentication code.
;                                         Default is 64.
;                  $bKey                - [optional] Some secret key. One cannot predict the final hash without it.
;                                         Default is "" (no key).
; Return values .: The hash (binary string of length $iHashSize).
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......: If you need the hash big data, see the incremental interface (_MC_Blake2b_Init,
;                  _MC_Blake2b_Update and _MC_Blake2b_Final)
; Related .......:
; Link ..........: https://monocypher.org/manual/hash
; Example .......: No
; ===============================================================================================================================
Func _MC_Blake2b($bMessage, $iHashSize = 64, $bKey = "")
	Local $tHash = DllStructCreate("byte[" & $iHashSize & "]")
	Local $tKey = __MC_binToStruct($bKey)
	Local $iKeySize = @extended
	Local $tMessage = __MC_binToStruct($bMessage)

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_blake2b_general", _
		"struct*", $tHash, _      ;       uint8_t *hash
		"uint_ptr", $iHashSize, _ ;       size_t  hash_size
		"struct*", $tKey, _       ; const uint8_t *key
		"uint_ptr", $iKeySize, _  ;       size_t  key_size
		"struct*", $tMessage, _   ; const uint8_t *message
		"uint_ptr", @extended _   ;       size_t  message_size
	)

	Return DllStructGetData($tHash, 1)
EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_Blake2b_Init
; Description ...:
; Syntax ........: _MC_Blake2b_Init([$iHashSize = 64[, $bKey = ""]])
; Parameters ....: $iHashSize           - [optional] Length of hash, in bytes. Must be between 1 and 64.
;                                         Anything below 32 is discouraged when using Blake2b as a general-purpose hash function;
;                                         anything below 16 is discouraged when using Blake2b as a message authentication code.
;                                         Default is 64.
;                  $bKey                - [optional] Some secret key. One cannot predict the final hash without it.
;                                         Default is "" (no key).
; Return values .: None
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........: https://monocypher.org/manual/hash
; Example .......: No
; ===============================================================================================================================
Func _MC_Blake2b_Init($iHashSize = 64, $bKey = "")
	Local $tHashCtx = DllStructCreate("uint64 Hash[8]; uint64 InputOffset[2]; uint64 Input[16]; uint_ptr InputIdx; uint_ptr HashSize") ; struct crypto_blake2b_ctx
	Local $tKey = __MC_binToStruct($bKey)

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_blake2b_general_init", _
		"struct*", $tHashCtx, _   ; crypto_blake2b_ctx *ctx
		"uint_ptr", $iHashSize, _ ;       size_t       hash_size
		"struct*", $tKey, _       ; const uint8_t      *key
		"uint_ptr", @extended _   ;       size_t       key_size
	)

	Return $tHashCtx
EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_Blake2b_Update
; Description ...:
; Syntax ........: _MC_Blake2b_Update($tHashCtx, $bMessage)
; Parameters ....: $tHashCtx            - a dll struct value.
;                  $bMessage            - a boolean value.
; Return values .: None
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _MC_Blake2b_Update($tHashCtx, $bMessage)
	Local $tMessage = __MC_binToStruct($bMessage)

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_blake2b_update", _
		"struct*", $tHashCtx, _ ; crypto_blake2b_ctx *ctx
		"struct*", $tMessage, _ ; const uint8_t      *message
		"uint_ptr", @extended _ ;       size_t       message_size
	)
EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_Blake2b_Final
; Description ...:
; Syntax ........: _MC_Blake2b_Final($tHashCtx)
; Parameters ....: $tHashCtx            - a dll struct value.
; Return values .: None
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _MC_Blake2b_Final($tHashCtx)
	Local $tHash = DllStructCreate("byte[" & $tHashCtx.HashSize & "]")

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_blake2b_final", _
		"struct*", $tHashCtx, _ ; crypto_blake2b_ctx *ctx
		"struct*", $tHash _     ; uint8_t            *hash
	)

	Return DllStructGetData($tHash, 1)
EndFunc

#EndRegion

#Region Password key derivation =================================================================================================
; https://monocypher.org/manual/argon2i

; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_Argon2i
; Description ...: Argon2i is a resource intensive password key derivation scheme optimised for the typical x86-like processor.
;                  It runs in constant time with respect to the contents of the password.
; Syntax ........: _MC_Argon2i($bPassword[, $iHashSize = 64[, $iNbBlocks = 100000[, $iNbIterations = 3[, $bSalt = ""[,
;                  $bKey = ""[, $bAd = ""]]]]]])
; Parameters ....: $bPassword           - The password to hash. It should be wiped with crypto_wipe() after being hashed.
;                  $iHashSize           - [optional] Length of hash, in bytes. This argument should be set to 32 or 64
;                                         for compatibility with the crypto_verify*() constant time comparison functions.
;                                         Default is 64.
;                  $iNbBlocks           - [optional] The number of blocks for the work area. Must be at least 8.
;                                         A value of 100000 (one hundred megabytes) is a good starting point.
;                                         If the computation takes too long, reduce this number.
;                                         If it is too fast, increase this number. If it is still too fast with all available
;                                         memory, increase nb_iterations.
;                                         Default is 100000.
;                  $iNbIterations       - [optional] The number of iterations. It must be at least 1. A value of 3 is strongly
;                                         recommended; any value lower than 3 enables significantly more efficient attacks.
;                                         Default is 3.
;                  $bSalt               - [optional] A password salt. This should be filled with random bytes,
;                                         generated separately for each password to be hashed (see _MC_RandomData).
;                                         Default is "" (no salt).
;                  $bKey                - [optional] A key to use in the hash. Can be NULL if key_size is zero.
;                                         The key is generally not needed, but it does have some uses. In the context of password
;                                         derivation, it would be stored separately from the password database, and would remain
;                                         secret even if an attacker were to steal the database. Note that changing the key
;                                         requires rehashing the user's password, which is only possible upon user login.
;                                         Default is "" (no key).
;                  $bAd                 - [optional] Additional data. This is additional data that goes into the hash, similar
;                                         to the authenticated encryption with authenticated data (AEAD) construction in
;                                         crypto_lock_aead(). This most likely has no practical application but is exposed
;                                         for the sake of completeness.
;                                         Default is "" (no additional data).
; Return values .: None
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........: https://monocypher.org/manual/argon2i
; Example .......: No
; ===============================================================================================================================
Func _MC_Argon2i($bPassword, $iHashSize = 64, $iNbBlocks = 100000, $iNbIterations = 3, $bSalt = "", $bKey = "", $bAd = "")
	Local $tPassword = __MC_binToStruct($bPassword)
	Local $iPasswordSize = @extended
	Local $tHash = DllStructCreate("byte[" & $iHashSize & "]")
	Local $pWorkArea = _MemGlobalAlloc($iNbBlocks * 1024)
	Local $tSalt = __MC_binToStruct($bSalt)
	Local $iSaltSize = @extended
	Local $tKey = __MC_binToStruct($bKey)
	Local $iKeySize = @extended
	Local $tAd = __MC_binToStruct($bAd)
	Local $iAdSize = @extended

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_argon2i_general", _
		"struct*", $tHash, _      ;       uint8_t  *hash
		"uint", $iHashSize, _     ;       uint32_t hash_size
		"ptr", $pWorkArea, _      ;       void     *work_area
		"uint", $iNbBlocks, _     ;       uint32_t nb_blocks
		"uint", $iNbIterations, _ ;       uint32_t nb_iterations
		"struct*", $tPassword, _  ; const uint8_t  *password
		"uint", $iPasswordSize, _ ;       uint32_t password_size
		"struct*", $tSalt, _      ; const uint8_t  *salt
		"uint", $iSaltSize, _     ;       uint32_t salt_size
		"struct*", $tKey, _       ; const uint8_t  *key
		"uint", $iKeySize, _      ;       uint32_t key_size
		"struct*", $tAd, _        ; const uint8_t  *ad
		"uint", $iAdSize _        ;       uint32_t ad_size
	)

	_MemGlobalFree($pWorkArea)
	Return DllStructGetData($tHash, 1)
EndFunc

#EndRegion

#Region Elliptic Curve Diffie-Hellman key exchange ==============================================================================
; https://monocypher.org/manual/key_exchange

; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_KeyExchange
; Description ...: Computes a shared key with your secret key and their public key.
; Syntax ........: _MC_KeyExchange($b32_YourSecretKey, $b32_TheirPublicKey)
; Parameters ....: $b32_YourSecretKey   - A 32-byte random number, known only to you.
;                  $b32_TheirPublicKey  - The public key of the other party.
; Return values .: 32 Bytes shared key.
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......: - Do not use the same secret key for both key exchanges and signatures.
;                    The public keys are different, and revealing both may leak information.
;                    (see _MC_KeyExchangePublicKey, _MC_SignPublicKey)
;                  - If a parameter is not the right size, program will exit.
; Related .......: _MC_KeyExchangePublicKey
; Link ..........: https://monocypher.org/manual/key_exchange
; Example .......: No
; ===============================================================================================================================
Func _MC_KeyExchange($b32_YourSecretKey, $b32_TheirPublicKey)
	Local $tYourSecretKey = __MC_binToStruct($b32_YourSecretKey, 32)
	Local $tTheirPublicKey = __MC_binToStruct($b32_TheirPublicKey, 32)
	Local $tSharedKey = DllStructCreate("byte[32]")

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_key_exchange", _
		"struct*", $tSharedKey, _     ;       uint8_t shared_key[32]
		"struct*", $tYourSecretKey, _ ; const uint8_t your_secret_key[32]
		"struct*", $tTheirPublicKey _ ; const uint8_t their_public_key[32]
	)

	Return DllStructGetData($tSharedKey, 1)
EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_KeyExchangePublicKey
; Description ...: Deterministically computes the public key from a random secret key.
; Syntax ........: _MC_KeyExchangePublicKey($b32_YourSecretKey)
; Parameters ....: $b32_YourSecretKey   - A 32-byte random number, known only to you.
; Return values .: 32 Bytes public key.
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......: - Do not use the same secret key for both key exchanges and signatures.
;                    The public keys are different, and revealing both may leak information.
;                    (see _MC_SignPublicKey)
;                  - If a parameter is not the right size, program will exit.
; Related .......: _MC_KeyExchange
; Link ..........: https://monocypher.org/manual/key_exchange
; Example .......: No
; ===============================================================================================================================
Func _MC_KeyExchangePublicKey($b32_YourSecretKey)
	Local $tYourSecretKey = __MC_binToStruct($b32_YourSecretKey, 32)
	Local $tYourPublicKey = DllStructCreate("byte[32]")

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_key_exchange_public_key", _
		"struct*", $tYourPublicKey, _ ;       uint8_t your_public_key[32]
		"struct*", $tYourSecretKey _  ; const uint8_t your_secret_key[32]
	)

	Return DllStructGetData($tYourPublicKey, 1)
EndFunc

#EndRegion

#Region Public key signatures ===================================================================================================
; https://monocypher.org/manual/sign

; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_SignPublicKey
; Description ...: Computes the public key of the specified secret key.
; Syntax ........: _MC_SignPublicKey($b32_SecretKey)
; Parameters ....: $b32_SecretKey       - A 32-byte random number, known only to you.
; Return values .: 32-byte public key.
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......: Do not use the same private key for both signatures and key exchanges. The public keys are different,
;                  and revealing both may leak information.
; Related .......:
; Link ..........: https://monocypher.org/manual/sign
; Example .......: No
; ===============================================================================================================================
Func _MC_SignPublicKey($b32_SecretKey)
	Local $tSecretKey = __MC_binToStruct($b32_SecretKey, 32)
	Local $tPublicKey = DllStructCreate("byte[32]")

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_sign_public_key", _
		"struct*", $tPublicKey, _ ;       uint8_t public_key[32]
		"struct*", $tSecretKey _  ; const uint8_t secret_key[32]
	)

	Return DllStructGetData($tPublicKey, 1)
EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_Sign
; Description ...: signs a message with secret_key.
; Syntax ........: _MC_Sign($bMessage, $b32_SecretKey, $b32_PublicKey)
; Parameters ....: $bMessage            - Message to sign.
;                  $b32_SecretKey       - A 32-byte random number, known only to you.
;                  $b32_PublicKey       - The public key, generated from secret_key with _MC_SignPublicKey().
; Return values .: 64-byte signature.
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......: The public key is optional, and will be recomputed if not provided.
;                  This recomputation doubles the execution time.
; Related .......:
; Link ..........: https://monocypher.org/manual/sign
; Example .......: No
; ===============================================================================================================================
Func _MC_Sign($bMessage, $b32_SecretKey, $b32_PublicKey = Default)
	Local $tSecretKey = __MC_binToStruct($b32_SecretKey, 32)
	Local $tPublicKey = $b32_PublicKey = Default ? 0 : __MC_binToStruct($b32_PublicKey, 32)
	Local $tSignature = DllStructCreate("byte[64]")
	Local $tMessage = __MC_binToStruct($bMessage)

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_sign", _
		"struct*", $tSignature, _ ;       uint8_t signature[64]
		"struct*", $tSecretKey, _ ; const uint8_t secret_key[32]
		"struct*", $tPublicKey, _ ; const uint8_t public_key[32]
		"struct*", $tMessage, _   ; const uint8_t *message
		"uint_ptr", @extended _   ;       size_t  message_size
	)

	Return DllStructGetData($tSignature, 1)
EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _MC_Check
; Description ...: checks that a given signature is genuine.
;                  Meaning, only someone who had the private key could have signed the message.
; Syntax ........: _MC_Check($bMessage, $b64_Signature, $b32_PublicKey)
; Parameters ....: $bMessage            - Message to sign.
;                  $b64_Signature       - 64-byte signature.
;                  $b32_PublicKey       - The public key, generated from secret_key with _MC_SignPublicKey().
; Return values .: True for legitimate message, False for forgeries.
; Author ........: matwachich at gmail dot com
; Modified ......:
; Remarks .......: It does not run in constant time. It does not have to in most threat models,
;                  because nothing is secret: everyone knows the public key, and the signature and message are rarely secret.
; Related .......:
; Link ..........: https://monocypher.org/manual/sign
; Example .......: No
; ===============================================================================================================================
Func _MC_Check($bMessage, $b64_Signature, $b32_PublicKey)
	Local $tSignature = __MC_binToStruct($b64_Signature, 64)
	Local $tPublicKey = __MC_binToStruct($b32_PublicKey, 32)
	Local $tMessage = __MC_binToStruct($bMessage)

	Local $aRet = DllCall($__gMonocypher_hDLL, "int:cdecl", "crypto_check", _
		"struct*", $tSignature, _ ; const uint8_t signature[64]
		"struct*", $tPublicKey, _ ; const uint8_t public_key[32]
		"struct*", $tMessage, _   ; const uint8_t *message
		"uint_ptr", @extended _   ;       size_t  message_size
	)

	Return $aRet[0] = 0
EndFunc

#EndRegion

#Region Incremental public key signatures =======================================================================================
; https://monocypher.org/manual/advanced/sign-incr

Func _MC_SignInitFirstPass($b32_SecretKey, $b32_PublicKey = Default)
	Local $tSecretKey = __MC_binToStruct($b32_SecretKey, 32)
	Local $tPublicKey = $b32_PublicKey = Default ? 0 : __MC_binToStruct($b32_PublicKey, 32)
	Local $tSignCtx = DllStructCreate("struct;struct;ptr;ptr;ptr;ptr;uint_ptr;endstruct;byte[96];byte[32];endstruct;struct;uint64[8];uint64[2];uint64[16];uint_ptr;uint_ptr;endstruct")

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_sign_init_first_pass", _
		"struct*", $tSignCtx, _   ; crypto_sign_ctx *ctx
		"struct*", $tSecretKey, _ ; const uint8_t   secret_key[32]
		"struct*", $tPublicKey _  ; const uint8_t   public_key[32]
	)

	Return $tSignCtx
EndFunc

Func _MC_SignInitSecondPass($tSignCtx)
	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_sign_init_second_pass", _
		"struct*", $tSignCtx _ ; crypto_sign_ctx *ctx
	)
EndFunc

Func _MC_SignUpdate($tSignCtx, $bMessage)
	Local $tMessage = __MC_binToStruct($bMessage)

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_sign_update", _
		"struct*", $tSignCtx, _ ; crypto_sign_ctx *ctx
		"struct*", $tMessage, _ ; const uint8_t   *message
		"uint_ptr", @extended _ ;       size_t    message_size
	)
EndFunc

Func _MC_SignFinal($tSignCtx)
	Local $tSignature = DllStructCreate("byte[64]")

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_sign_final", _
		"struct*", $tSignCtx, _  ; crypto_sign_ctx *ctx
		"struct*", $tSignature _ ; uint8_t         signature[64]
	)

	Return DllStructGetData($tSignature, 1)
EndFunc

Func _MC_CheckInit($b64_Signature, $b32_PublicKey)
	Local $tSignature = __MC_binToStruct($b64_Signature, 64)
	Local $tPublicKey = __MC_binToStruct($b32_PublicKey, 32)
	Local $tCheckCtx = DllStructCreate("struct;struct;ptr;ptr;ptr;ptr;uint_ptr;endstruct;byte[96];byte[32];endstruct;struct;uint64[8];uint64[2];uint64[16];uint_ptr;uint_ptr;endstruct")

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_check_init", _
		"struct*", $tCheckCtx, _   ; crypto_check_ctx *ctx
		"struct*", $tSignature, _  ; const uint8_t    signature[64],
		"struct*", $tPublicKey _   ; const uint8_t    public_key[32]
	)

	Return $tCheckCtx
EndFunc

Func _MC_CheckUpdate($tCheckCtx, $bMessage)
	Local $tMessage = __MC_binToStruct($bMessage)

	DllCall($__gMonocypher_hDLL, "none:cdecl", "crypto_check_update", _
		"struct*", $tCheckCtx, _ ; crypto_check_ctx *ctx
		"struct*", $tMessage, _  ; const uint8_t    *message
		"uint_ptr", @extended _  ;       size_t     message_size
	)
EndFunc

Func _MC_CheckFinal($tCheckCtx)
	Return DllCall($__gMonocypher_hDLL, "int:cdecl", "crypto_check_final", _
		"struct*", $tCheckCtx _ ; crypto_check_ctx *ctx
	)[0] = 0
EndFunc

#EndRegion

#Region Utility functions =======================================================================================================

Func _MC_RandomData($iLen)
	Local $tBuff = DllStructCreate("byte[" & $iLen & "]")
	If _Crypt_GenRandom($tBuff, $iLen) Then
		Return DllStructGetData($tBuff, 1)
	Else
		Return Binary("")
	EndIf
EndFunc

#EndRegion

#Region Internal functions ======================================================================================================

Func __MC_binToStruct($bBin, $iLen = Default)
	If Not IsBinary($bBin) Then $bBin = StringToBinary($bBin, 4)

	If $iLen == Default Then
		$iLen = BinaryLen($bBin)
	Else
		If $iLen <> BinaryLen($bBin) Then
			MsgBox(16, @ScriptName, "Invalid data length (expected " & $iLen & " byte(s), got " & BinaryLen($bBin) & " byte(s))")
			Exit -1
		EndIf
	EndIf

	If $iLen <= 0 Then Return SetError(0, 0, 0)

	Local $tStruct = DllStructCreate("byte[" & $iLen & "]")
	DllStructSetData($tStruct, 1, $bBin)
	Return SetError(0, $iLen, $tStruct)
EndFunc

#EndRegion
