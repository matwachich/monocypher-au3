#NoTrayIcon
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=n
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

;~ #include <_Dbug.au3>

#include <Crypt.au3>
#include "monocypher.au3"

_Monocypher_Startup()
If @error Then Exit -1

Const $bKey32 = _GetRandom(32) ; some random 32 bytes key used in the tests
Const $bNonce24 = _GetRandom(24) ; some random 24 bytes nonce used in the tests

Const $bMessage = StringToBinary("Salut la compagnie!!! Ceci est un simple message de test.", 4)

; -------------------------------------------------------------------------------------------------
; Lock/Unlock interface (simple)

Dim $bMac

$bLocked = _Monocypher_Lock($bKey32, $bNonce24, $bMessage, $bMac)
$bUnlocked = _Monocypher_Unlock($bKey32, $bNonce24, $bLocked, $bMac)
If $bUnlocked <> $bMessage Then
	ConsoleWrite("Lock/Unlock interface test failed!!!" & @CRLF)
	Exit
EndIf

; -------------------------------------------------------------------------------------------------
; Lock/Unlock interface (incremental)

$tLock = _Monocypher_Lock_Init($bKey32, $bNonce24)

$bLocked = Binary("")
For $i = 1 To 3
	$bLocked &= _Monocypher_Lock_Update($tLock, $bMessage)
	$bLocked &= _Monocypher_Lock_Update($tLock, StringToBinary(@CRLF, 4))
Next

$bMac = _Monocypher_Lock_Final($tLock)

; ---

$tUnlock = _Monocypher_Unlock_Init($bKey32, $bNonce24)

$bUnlocked = _Monocypher_Unlock_Update($tUnlock, $bLocked)

If _Monocypher_Unlock_Final($tUnlock, $bMac) Then
	If $bUnlocked <> $bMessage & StringToBinary(@CRLF, 4) & $bMessage & StringToBinary(@CRLF, 4) & $bMessage & StringToBinary(@CRLF, 4) Then
		ConsoleWrite("Lock/Unlock incremental interface test failed!!!" & @CRLF)
		Exit
	EndIf
Else
	ConsoleWrite("Lock/Unlock incremental interface MAC verification failed!!!" & @CRLF)
	Exit
EndIf

; ---

Func _GetRandom($iLen)
	Local $tBuff = DllStructCreate("byte[" & $iLen & "]")
	If _Crypt_GenRandom($tBuff, $iLen) Then
		Return DllStructGetData($tBuff, 1)
	Else
		Return Binary("")
	EndIf
EndFunc

