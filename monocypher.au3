#include-once

;~ #ifndef MONOCYPHER_H
;~ #define MONOCYPHER_H

;~ #include <inttypes.h>
;~ #include <stddef.h>

#include "monocypher_dlls.au3"

Global $__gMC_hDll = -1, $__gMC_sDllPath = ""

Func _Monocypher_Startup($sDllPath = @ScriptDir)
	If $__gMC_hDll == -1 Then
		If @AutoItX64 Then
			$__gMC_sDllPath = $sDllPath & "\monocypher64.dll"
			_binFile_monocypher_x64_dll($__gMC_sDllPath)
		Else
			$__gMC_sDllPath = $sDllPath & "\monocypher32.dll"
			_binFile_monocypher_x86_dll($__gMC_sDllPath)
		EndIf
		$__gMC_hDll = DllOpen($__gMC_sDllPath)
		If $__gMC_hDll == -1 Then Return SetError(1, 0, 0)
		OnAutoItExitRegister(_Monocypher_Shutdown)
	EndIf
	Return 1
EndFunc

Func _Monocypher_Shutdown()
	If $__gMC_hDll <> -1 Then DllClose($__gMC_hDll)
	FileDelete($__gMC_sDllPath)
	$__gMC_hDll = -1
	Return 1
EndFunc

;~ ////////////////////////
;~ /// Type definitions ///
;~ ////////////////////////

;~ // Do not rely on the size or content on any of those types,
;~ // they may change without notice.

;~ // Chacha20
;~ typedef struct {
;~     uint32_t input[16]; // current input, unencrypted
;~     uint32_t pool [16]; // last input, encrypted
;~     size_t   pool_idx;  // pointer to random_pool
;~ } crypto_chacha_ctx;
Const $__gMC_sTagChachaCtx = "uint input[16]; uint pool[16]; uint_ptr pool_idx"

;~ // Poly1305
;~ typedef struct {
;~     uint32_t r[4];   // constant multiplier (from the secret key)
;~     uint32_t h[5];   // accumulated hash
;~     uint32_t c[5];   // chunk of the message
;~     uint32_t pad[4]; // random number added at the end (from the secret key)
;~     size_t   c_idx;  // How many bytes are there in the chunk.
;~ } crypto_poly1305_ctx;
Const $__gMC_sTagPoly1305Ctx = "uint r[4]; uint h[5]; uint c[5]; uint pad[4]; uint_ptr c_idx"

;~ // Authenticated encryption
;~ typedef struct {
;~     crypto_chacha_ctx   chacha;
;~     crypto_poly1305_ctx poly;
;~     uint64_t            ad_size;
;~     uint64_t            message_size;
;~     int                 ad_phase;
;~ } crypto_lock_ctx;
;~ #define crypto_unlock_ctx crypto_lock_ctx
Const $__gMC_sTagLockCtx = "struct; " & $__gMC_sTagChachaCtx & "; endstruct; struct; " & $__gMC_sTagPoly1305Ctx & "; endstruct; uint64 ad_size; uint64 message_size; int ad_phase"
Const $__gMC_sTagUnlockCtx = $__gMC_sTagLockCtx

;~ // Hash (Blake2b)
;~ typedef struct {
;~     uint64_t hash[8];
;~     uint64_t input_offset[2];
;~     uint64_t input[16];
;~     size_t   input_idx;
;~     size_t   hash_size;
;~ } crypto_blake2b_ctx;
Const $__gMC_sTagBlack2bCtx = "uint64 hash[8]; uint64 input_offset[2]; uint64 input[16]; uint_ptr input_idx; uint_ptr hash_size"

;~ // Signatures (EdDSA)
;~ #ifdef ED25519_SHA512
;~     #include "sha512.h"
;~     typedef crypto_sha512_ctx crypto_hash_ctx;
;~ #else
;~     typedef crypto_blake2b_ctx crypto_hash_ctx;
;~ #endif

;~ typedef struct {
;~     crypto_hash_ctx hash;
;~     uint8_t buf[96];
;~     uint8_t pk [32];
;~ } crypto_sign_ctx;
Const $__gMC_sTagSignCtx = "struct; " & $__gMC_sTagBlack2bCtx & "; endstruct; byte buf[96]; byte pk[32]"

;~ typedef struct {
;~     crypto_hash_ctx hash;
;~     uint8_t sig[64];
;~     uint8_t pk [32];
;~ } crypto_check_ctx;
Const $__gMC_sTagCheckCtx = "struct; " & $__gMC_sTagBlack2bCtx & "; endstruct; byte sig[64]; byte pk[32]"


;~ ////////////////////////////
;~ /// High level interface ///
;~ ////////////////////////////

;~ // Constant time comparisons
;~ // -------------------------

;~ // Return 0 if a and b are equal, -1 otherwise
;~ int crypto_verify16(const uint8_t a[16], const uint8_t b[16]);
;~ int crypto_verify32(const uint8_t a[32], const uint8_t b[32]);
;~ int crypto_verify64(const uint8_t a[64], const uint8_t b[64]);


;~ // Erase sensitive data
;~ // --------------------

;~ // Please erase all copies
;~ void crypto_wipe(void *secret, size_t size);


;~ // Authenticated encryption
;~ // ------------------------

;~ // Direct interface
;~ void crypto_lock(uint8_t        mac[16],
;~                  uint8_t       *cipher_text,
;~                  const uint8_t  key[32],
;~                  const uint8_t  nonce[24],
;~                  const uint8_t *plain_text, size_t text_size);
Func _Monocypher_Lock($bKey32, $bNonce24, $bPlainText, ByRef $bMac16)
	If BinaryLen($bPlainText) == 0 Then Return Binary("")
	Local $tKey = __monocypher_binToStruct($bKey32, 32)
	Local $tNonce = __monocypher_binToStruct($bNonce24, 24)
	Local $tMac = DllStructCreate("byte[16]")
	Local $tData = __monocypher_binToStruct($bPlainText)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_lock", "struct*", $tMac, "struct*", $tData, "struct*", $tKey, "struct*", $tNonce, "struct*", $tData, "uint", @extended)
	$bMac16 = DllStructGetData($tMac, 1)
	Return DllStructGetData($tData, 1)
EndFunc

;~ int crypto_unlock(uint8_t       *plain_text,
;~                   const uint8_t  key[32],
;~                   const uint8_t  nonce[24],
;~                   const uint8_t  mac[16],
;~                   const uint8_t *cipher_text, size_t text_size);
Func _Monocypher_Unlock($bKey32, $bNonce24, $bCipherText, $bMac16)
	If BinaryLen($bCipherText) == 0 Then Return Binary("")
	Local $tKey = __monocypher_binToStruct($bKey32, 32)
	Local $tNonce = __monocypher_binToStruct($bNonce24, 24)
	Local $tMac = __monocypher_binToStruct($bMac16, 16)
	Local $tData = __monocypher_binToStruct($bCipherText)
	Local $aRet = DllCall($__gMC_hDll, "int:cdecl", "crypto_unlock", "struct*", $tData, "struct*", $tKey, "struct*", $tNonce, "struct*", $tMac, "struct*", $tData, "uint", @extended)
	If @error Then Return SetError(@error, 0, 0)
	Return SetError($aRet[0] == -1 ? -1 : 0, 0, $aRet[0] == -1 ? Null : DllStructGetData($tData, 1))
EndFunc

;~ // Direct interface with additional data
;~ void crypto_lock_aead(uint8_t        mac[16],
;~                       uint8_t       *cipher_text,
;~                       const uint8_t  key[32],
;~                       const uint8_t  nonce[24],
;~                       const uint8_t *ad        , size_t ad_size,
;~                       const uint8_t *plain_text, size_t text_size);
;~ Func _Monocypher_Lock_Aead($bKey32, $bNonce24, $bPlainText, $bAd, ByRef $bMac16)

;~ int crypto_unlock_aead(uint8_t       *plain_text,
;~                        const uint8_t  key[32],
;~                        const uint8_t  nonce[24],
;~                        const uint8_t  mac[16],
;~                        const uint8_t *ad         , size_t ad_size,
;~                        const uint8_t *cipher_text, size_t text_size);

;~ // Incremental interface (encryption)
;~ void crypto_lock_init(crypto_lock_ctx *ctx,
;~                       const uint8_t    key[32],
;~                       const uint8_t    nonce[24]);
Func _Monocypher_Lock_Init($bKey32, $bNonce24)
	Local $tLockCtx = DllStructCreate($__gMC_sTagLockCtx)
	Local $tKey = __monocypher_binToStruct($bKey32, 32)
	Local $tNonce = __monocypher_binToStruct($bNonce24, 24)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_lock_init", "struct*", $tLockCtx, "struct*", $tKey, "struct*", $tNonce)
	If @error Then Return SetError(@error, 0, 0)
	Return $tLockCtx
EndFunc

;~ void crypto_lock_auth_ad(crypto_lock_ctx *ctx,
;~                          const uint8_t   *message,
;~                          size_t           message_size);
Func _Monocypher_Lock_Auth_Ad(ByRef $tLockCtx, $bMessage)
	If BinaryLen($bMessage) == 0 Then Return Binary("")
	Local $tMessage = __monocypher_binToStruct($bMessage)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_lock_auth_ad", "struct*", $tLockCtx, "struct*", $tMessage, "uint", @extended)
	If @error Then Return SetError(@error, 0, 0)
EndFunc

;~ void crypto_lock_auth_message(crypto_lock_ctx *ctx,
;~                               const uint8_t *cipher_text, size_t text_size);
Func _Monocypher_Lock_Auth_Message(ByRef $tLockCtx, $bCipherText)
	If BinaryLen($bCipherText) == 0 Then Return Binary("")
	Local $tCipherText = __monocypher_binToStruct($bCipherText)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_lock_auth_message", "struct*", $tLockCtx, "struct*", $tCipherText, "uint", @extended)
	If @error Then Return SetError(@error, 0, 0)
EndFunc

;~ void crypto_lock_update(crypto_lock_ctx *ctx,
;~                         uint8_t         *cipher_text,
;~                         const uint8_t   *plain_text,
;~                         size_t           text_size);
Func _Monocypher_Lock_Update(ByRef $tLockCtx, $bPlainText)
	If BinaryLen($bPlainText) == 0 Then Return Binary("")
	Local $tData = __monocypher_binToStruct($bPlainText)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_lock_update", "struct*", $tLockCtx, "struct*", $tData, "struct*", $tData, "uint", @extended)
	If @error Then Return SetError(@error, 0, 0)
	Return DllStructGetData($tData, 1)
EndFunc

;~ void crypto_lock_final(crypto_lock_ctx *ctx, uint8_t mac[16]);
Func _Monocypher_Lock_Final(ByRef $tLockCtx)
	Local $tMac = DllStructCreate("byte[16]")
	DllCall($__gMC_hDll, "none:cdecl", "crypto_lock_final", "struct*", $tLockCtx, "struct*", $tMac)
	If @error Then Return SetError(@error, 0, 0)
	Return DllStructGetData($tMac, 1)
EndFunc


;~ // Incremental interface (decryption)
;~ #define crypto_unlock_init         crypto_lock_init
Func _Monocypher_Unlock_Init($bKey32, $bNonce24)
	Local $vRet = _Monocypher_Lock_Init($bKey32, $bNonce24)
	Return SetError(@error, @extended, $vRet)
EndFunc

;~ #define crypto_unlock_auth_ad      crypto_lock_auth_ad
Func _Monocypher_Unlock_Auth_Ad(ByRef $tUnlockCtx, $bMessage)
	Local $vRet = _Monocypher_Lock_Auth_Ad($tUnlockCtx, $bMessage)
	Return SetError(@error, @extended, $vRet)
EndFunc

;~ #define crypto_unlock_auth_message crypto_lock_auth_message
Func _Monocypher_Unlock_Auth_Message(ByRef $tUnlockCtx, $bCipherText)
	Local $vRet = _Monocypher_Lock_Auth_Message($tUnlockCtx, $bCipherText)
	Return SetError(@error, @extended, $vRet)
EndFunc

;~ void crypto_unlock_update(crypto_unlock_ctx *ctx,
;~                           uint8_t           *plain_text,
;~                           const uint8_t     *cipher_text,
;~                           size_t             text_size);
Func _Monocypher_Unlock_Update(ByRef $tUnlockCtx, $bCipherText)
	If BinaryLen($bCipherText) == 0 Then Return Binary("")
	Local $tData = __monocypher_binToStruct($bCipherText)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_unlock_update", "struct*", $tUnlockCtx, "struct*", $tData, "struct*", $tData, "uint", @extended)
	If @error Then Return SetError(@error, 0, 0)
	Return DllStructGetData($tData, 1)
EndFunc

;~ int crypto_unlock_final(crypto_unlock_ctx *ctx, const uint8_t mac[16]);
Func _Monocypher_Unlock_Final(ByRef $tUnlockCtx, $bMac16)
	Local $tMac = __monocypher_binToStruct($bMac16, 16)
	Local $aRet = DllCall($__gMC_hDll, "int:cdecl", "crypto_unlock_final", "struct*", $tUnlockCtx, "struct*", $tMac)
	If @error Then SetError(@error, 0, 0)
	Return SetError($aRet[0] == -1 ? -1 : 0, 0, $aRet[0] == -1 ? False : True)
EndFunc


;~ // General purpose hash (Blake2b)
;~ // ------------------------------

;~ // Direct interface
;~ void crypto_blake2b(uint8_t hash[64],
;~                     const uint8_t *message, size_t message_size);
Func _Monocypher_Blake2b($bMessage)
	If BinaryLen($bMessage) == 0 Then Return Binary("")
	Local $tHash = DllStructCreate("byte[64]")
	Local $tMessage = __monocypher_binToStruct($bMessage)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_blake2b", "struct*", $tHash, "struct*", $tMessage, "uint", @extended)
	If @error Then Return SetError(@error, 0, "")
	Return DllStructGetData($tHash, 1)
EndFunc

;~ void crypto_blake2b_general(uint8_t       *hash    , size_t hash_size,
;~                             const uint8_t *key     , size_t key_size, // optional
;~                             const uint8_t *message , size_t message_size);
Func _Monocypher_Blake2b_General($bMessage, $iHashSize = 64, $bKey0_64 = "")
	If BinaryLen($bMessage) == 0 Then Return Binary("")
	If $iHashSize < 1 Or $iHashSize > 64 Then Return SetError(-1, 0, "")
	Local $iKeyLen = BinaryLen($bKey0_64)
	If $iKeyLen < 0 Or $iKeyLen > 64 Then Return SetError(-1, 0, "")

	Local $tKey = __monocypher_binToStruct($bKey0_64)
	Local $tHash = DllStructCreate("byte[" & $iHashSize & "]")
	Local $tMessage = __monocypher_binToStruct($bMessage)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_blake2b_general", "struct*", $tHash, "uint", $iHashSize, "struct*", $tKey, "uint", $iKeyLen, "struct*", $tMessage, "uint", @extended)
	If @error Then Return SetError(@error, 0, "")
	Return DllStructGetData($tHash, 1)
EndFunc

;~ // Incremental interface
;~ void crypto_blake2b_init  (crypto_blake2b_ctx *ctx);
Func _Monocypher_Blake2b_Init($iHashSize = 64, $bKey0_64 = "")
	Local $tBlake2bCtx = DllStructCreate($__gMC_sTagBlack2bCtx)
	If $bKey0_64 == "" And $iHashSize == 64 Then
		DllCall($__gMC_hDll, "none:cdecl", "crypto_blake2b_init", "struct*", $tBlake2bCtx)
	Else
		If $iHashSize < 1 Or $iHashSize > 64 Then Return SetError(-1, 0, 0)
		Local $iKeyLen = BinaryLen($bKey0_64)
		If $iKeyLen < 0 Or $iKeyLen > 64 Then Return SetError(-1, 0, 0)

		Local $tKey = __monocypher_binToStruct($bKey0_64)
		DllCall($__gMC_hDll, "none:cdecl", "crypto_blake2b_general_init", "struct*", $tBlake2bCtx, "uint", $iHashSize, "struct*", $tKey, "uint", $iKeyLen)
	EndIf
	If @error Then Return SetError(@error, 0, 0)
	Return $tBlake2bCtx
EndFunc

;~ void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
;~                            const uint8_t *message, size_t message_size);
Func _Monocypher_Blake2b_Update(ByRef $tBlake2bCtx, $bPlainText)
	If BinaryLen($bPlainText) == 0 Then Return 0
	Local $tMessage = __monocypher_binToStruct($bPlainText)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_blake2b_update", "struct*", $tBlake2bCtx, "struct*", $tMessage, "uint", @extended)
	If @error Then Return SetError(@error, 0, 0)
EndFunc

;~ void crypto_blake2b_final (crypto_blake2b_ctx *ctx, uint8_t *hash);
Func _Monocypher_Blake2b_Final(ByRef $tBlake2bCtx)
	Local $tHash = DllStructCreate("byte[" & DllStructGetData($tBlake2bCtx, "hash_size") & "]")
	DllCall($__gMC_hDll, "none:cdecl", "crypto_blake2b_final", "struct*", $tBlake2bCtx, "struct*", $tHash)
	If @error Then Return SetError(@error, 0, "")
	Return DllStructGetData($tHash, 1)
EndFunc

;~ void crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t hash_size,
;~                                  const uint8_t      *key, size_t key_size);
Func _Monocypher_Blake2b_General_Init($bKey0_64 = "", $iHashSize = 64)
	Local $vRet = _Monocypher_Blake2b_Init($bKey0_64, $iHashSize)
	Return SetError(@error, @extended, $vRet)
EndFunc


;~ // Password key derivation (Argon2 i)
;~ // ----------------------------------
;~ void crypto_argon2i(uint8_t       *hash,      uint32_t hash_size,     // >= 4
;~                     void          *work_area, uint32_t nb_blocks,     // >= 8
;~                     uint32_t       nb_iterations,                     // >= 1
;~                     const uint8_t *password,  uint32_t password_size,
;~                     const uint8_t *salt,      uint32_t salt_size);
Func _Monocypher_Argon2i($bPassword, $bSalt, $iHashSize = 64, $iBlocks = 10000, $iIterations = 3)
	If BinaryLen($bPassword) <= 0 Then Return Binary("")
	If $iHashSize <= 0 Or $iBlocks < 8 Or $iIterations < 1 Or BinaryLen($bSalt) < 8 Then Return SetError(1, 0, "")
	Local $tPassword = __monocypher_binToStruct($bPassword)
	Local $iPasswordSize = @extended
	Local $tSalt = __monocypher_binToStruct($bSalt)
	Local $iSaltSize = @extended
	Local $tHash = DllStructCreate("byte[" & $iHashSize & "]")
	Local $tWorkArea = DllStructCreate("byte[" & $iBlocks * 1024 & "]")
	DllCall($__gMC_hDll, "none:cdecl", "crypto_argon2i", _
		"struct*", $tHash, "uint", $iHashSize, _
		"struct*", $tWorkArea, "uint", $iBlocks, "uint", $iIterations, _
		"struct*", $tPassword, "uint", $iPasswordSize, _
		"struct*", $tSalt, "uint", $iSaltSize _
	)
	Return DllStructGetData($tHash, 1)
EndFunc

;~ void crypto_argon2i_general(uint8_t       *hash,      uint32_t hash_size,// >= 4
;~                             void          *work_area, uint32_t nb_blocks,// >= 8
;~                             uint32_t       nb_iterations,                // >= 1
;~                             const uint8_t *password,  uint32_t password_size,
;~                             const uint8_t *salt,      uint32_t salt_size,// >= 8
;~                             const uint8_t *key,       uint32_t key_size,
;~                             const uint8_t *ad,        uint32_t ad_size);


;~ // Key exchange (x25519 + HChacha20)
;~ // ---------------------------------
;~ #define crypto_key_exchange_public_key crypto_x25519_public_key
Func _Monocypher_Key_Exchange_Public_Key($bSecretKey32)
	Local $vRet = _Monocypher_x25519_public_key($bSecretKey32)
	Return SetError(@error, @extended, $vRet)
EndFunc

;~ int crypto_key_exchange(uint8_t       shared_key      [32],
;~                         const uint8_t your_secret_key [32],
;~                         const uint8_t their_public_key[32]);
Func _Monocypher_Key_Exchange($bYourSecretKey32, $bTheirPublicKey32)
	Local $tYourSecret = __monocypher_binToStruct($bYourSecretKey32, 32)
	Local $tTheirPublic = __monocypher_binToStruct($bTheirPublicKey32, 32)
	Local $tSharedKey = DllStructCreate("byte[32]")
	Local $aRet = DllCall($__gMC_hDll, "int:cdecl", "crypto_key_exchange", "struct*", $tSharedKey, "struct*", $tYourSecret, "struct*", $tTheirPublic)
	If @error Then Return SetError(@error, 0, 0)
	Return SetError($aRet[0] == -1 ? -1 : 0, 0, $aRet[0] == -1 ? Null : DllStructGetData($tSharedKey, 1))
EndFunc


;~ // Signatures (EdDSA with curve25519 + Blake2b)
;~ // --------------------------------------------

;~ // Generate public key
;~ void crypto_sign_public_key(uint8_t        public_key[32],
;~                             const uint8_t  secret_key[32]);
Func _Monocypher_Sign_Public_Key($bSecretKey32)
	Local $tPublic = DllStructCreate("byte[32]")
	Local $tSecret = __monocypher_binToStruct($bSecretKey32, 32)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_sign_public_key", "struct*", $tPublic, "struct*", $tSecret)
	If @error Then Return SetError(@error, 0, 0)
	Return DllStructGetData($tPublic, 1)
EndFunc

;~ // Direct interface
;~ void crypto_sign(uint8_t        signature [64],
;~                  const uint8_t  secret_key[32],
;~                  const uint8_t  public_key[32], // optional, may be 0
;~                  const uint8_t *message, size_t message_size);
Func _Monocypher_Sign($bSecretKey32, $bPublicKey32, $bMessage)
	Local $tSignature = DllStructCreate("byte[64]")
	Local $tSecret = __monocypher_binToStruct($bSecretKey32, 32)
	Local $tPublic = $bPublicKey32 ? __monocypher_binToStruct($bPublicKey32, 32) : 0
	Local $tMessage = __monocypher_binToStruct($bMessage)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_sign", "struct*", $tSignature, "struct*", $tSecret, "struct*", $tPublic, "struct*", $tMessage, "uint", @extended)
	If @error Then Return SetError(@error, 0, "")
	Return DllStructGetData($tSignature, 1)
EndFunc

;~ int crypto_check(const uint8_t  signature [64],
;~                  const uint8_t  public_key[32],
;~                  const uint8_t *message, size_t message_size);
Func _Monocypher_Check($bSignature64, $bPublicKey32, $bMessage)
	Local $tSignature = __monocypher_binToStruct($bSignature64, 64)
	Local $tPublic = __monocypher_binToStruct($bPublicKey32, 32)
	Local $tMessage = __monocypher_binToStruct($bMessage)
	Local $aRet = DllCall($__gMC_hDll, "int:cdecl", "crypto_check", "struct*", $tSignature, "struct*", $tPublic, "struct*", $tMessage, "uint", @extended)
	If @error Then Return SetError(@error, 0, Null)
	Return $aRet[0] == 0
EndFunc

;~ // Incremental interface for signatures (2 passes)
;~ void crypto_sign_init_first_pass(crypto_sign_ctx *ctx,
;~                                  const uint8_t  secret_key[32],
;~                                  const uint8_t  public_key[32]);
Func _Monocypher_Sign_Init_First_Pass($bSecretKey32, $bPublicKey32)
	Local $tSignCtx = DllStructCreate($__gMC_sTagSignCtx)
	Local $tSecret = __monocypher_binToStruct($bSecretKey32, 32)
	Local $tPublic = $bPublicKey32 ? __monocypher_binToStruct($bPublicKey32, 32) : 0
	DllCall($__gMC_hDll, "none:cdecl", "crypto_sign_init_first_pass", "struct*", $tSignCtx, "struct*", $tSecret, "struct*", $tPublic)
	If @error Then Return SetError(@error, 0, 0)
	Return $tSignCtx
EndFunc

;~ void crypto_sign_update(crypto_sign_ctx *ctx,
;~                         const uint8_t *message, size_t message_size);
Func _Monocypher_Sign_Update(ByRef $tSignCtx, $bMessage)
	Local $tMessage = __monocypher_binToStruct($bMessage)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_sign_update", "struct*", $tSignCtx, "struct*", $tMessage, "uint", @extended)
	If @error Then Return SetError(@error, 0, 0)
	Return True
EndFunc

;~ void crypto_sign_init_second_pass(crypto_sign_ctx *ctx);
Func _Monocypher_Sign_Init_Second_Pass(ByRef $tSignCtx)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_sign_init_second_pass", "struct*", $tSignCtx)
	If @error Then Return SetError(@error, 0, 0)
	Return $tSignCtx
EndFunc

;~ // use crypto_sign_update() again.
;~ void crypto_sign_final(crypto_sign_ctx *ctx, uint8_t signature[64]);
Func _Monocypher_Sign_Final(ByRef $tSignCtx)
	Local $tSignature = DllStructCreate("byte[64]")
	DllCall($__gMC_hDll, "none:cdecl", "crypto_sign_final", "struct*", $tSignCtx, "struct*", $tSignature)
	If @error Then Return SetError(@error, 0, "")
	Return DllStructGetData($tSignature, 1)
EndFunc

;~ // Incremental interface for verification (1 pass)
;~ void crypto_check_init  (crypto_check_ctx *ctx,
;~                          const uint8_t signature[64],
;~                          const uint8_t public_key[32]);
Func _Monocypher_Check_Init($bSignature64, $bPublicKey32)
	Local $tCheckCtx = DllStructCreate($__gMC_sTagCheckCtx)
	Local $tSignature = __monocypher_binToStruct($bSignature64, 64)
	Local $tPublic = __monocypher_binToStruct($bPublicKey32, 32)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_check_init", "struct*", $tCheckCtx, "struct*", $tSignature, "struct*", $tPublic)
	If @error Then Return SetError(@error, 0, 0)
	Return $tCheckCtx
EndFunc

;~ void crypto_check_update(crypto_check_ctx *ctx,
;~                          const uint8_t *message, size_t message_size);
Func _Monocypher_Check_Update(ByRef $tCheckCtx, $bMessage)
	Local $tMessage = __monocypher_binToStruct($bMessage)
	DllCall($__gMC_hDll, "none:cdecl", "crypto_check_update", "struct*", $tCheckCtx, "struct*", $tMessage, "uint", @extended)
	If @error Then Return SetError(@error, 0, False)
	Return True
EndFunc

;~ int crypto_check_final  (crypto_check_ctx *ctx);
Func _Monocypher_Check_Final(ByRef $tCheckCtx)
	Local $aRet = DllCall($__gMC_hDll, "int:cdecl", "crypto_check_final", "struct*", $tCheckCtx)
	If @error Then Return SetError(@error, 0, Null)
	Return $aRet[0] == 0
EndFunc


;~ ////////////////////////////
;~ /// Low level primitives ///
;~ ////////////////////////////

;~ // For experts only.  You have been warned.


;~ // Chacha20
;~ // --------

;~ // Specialised hash.
;~ void crypto_chacha20_H(uint8_t       out[32],
;~                        const uint8_t key[32],
;~                        const uint8_t in [16]);

;~ void crypto_chacha20_init(crypto_chacha_ctx *ctx,
;~                           const uint8_t      key[32],
;~                           const uint8_t      nonce[8]);

;~ void crypto_chacha20_x_init(crypto_chacha_ctx *ctx,
;~                             const uint8_t      key[32],
;~                             const uint8_t      nonce[24]);

;~ void crypto_chacha20_set_ctr(crypto_chacha_ctx *ctx, uint64_t ctr);

;~ void crypto_chacha20_encrypt(crypto_chacha_ctx *ctx,
;~                              uint8_t           *cipher_text,
;~                              const uint8_t     *plain_text,
;~                              size_t             text_size);

;~ void crypto_chacha20_stream(crypto_chacha_ctx *ctx,
;~                             uint8_t *stream, size_t size);


;~ // Poly 1305
;~ // ---------

;~ // Direct interface
;~ void crypto_poly1305(uint8_t        mac[16],
;~                      const uint8_t *message, size_t message_size,
;~                      const uint8_t  key[32]);

;~ // Incremental interface
;~ void crypto_poly1305_init  (crypto_poly1305_ctx *ctx, const uint8_t key[32]);
;~ void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
;~                             const uint8_t *message, size_t message_size);
;~ void crypto_poly1305_final (crypto_poly1305_ctx *ctx, uint8_t mac[16]);


;~ // X-25519
;~ // -------
;~ void crypto_x25519_public_key(uint8_t       public_key[32],
;~                               const uint8_t secret_key[32]);
Func _Monocypher_x25519_public_key($bSecretKey32)
	Local $tSecret = __monocypher_binToStruct($bSecretKey32, 32)
	Local $tPublic = DllStructCreate("byte[32]")
	DllCall($__gMC_hDll, "none:cdecl", "crypto_x25519_public_key", "struct*", $tPublic, "struct*", $tSecret)
	If @error Then Return SetError(@error, 0, 0)
	Return DllStructGetData($tPublic, 1)
EndFunc

;~ int crypto_x25519(uint8_t       raw_shared_secret[32],
;~                   const uint8_t your_secret_key  [32],
;~                   const uint8_t their_public_key [32]);

;~ #endif // MONOCYPHER_H

; -------------------------------------------------------------------------------------------------

Func __monocypher_binToStruct($bBin, $iLen = Default)
	If Not IsBinary($bBin) Then $bBin = StringToBinary($bBin, 4)
	If $iLen == Default Then $iLen = BinaryLen($bBin)
	Local $tStruct = DllStructCreate("byte[" & $iLen & "]")
	DllStructSetData($tStruct, 1, $bBin)
	Return SetError(0, $iLen, $tStruct)
EndFunc
