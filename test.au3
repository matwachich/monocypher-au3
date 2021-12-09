#NoTrayIcon
#include "monocypher.au3"

_MC_Startup("monocypher" & (@AutoItX64 ? "64" : "") & ".dll")
OnAutoItExitRegister(_MC_Shutdown)

#Region Authenticated encryption

$sPlainData = "Hello, world!"

$bNonce = _MC_RandomData(24)
Dim $bMac

; lock
$sPassword = InputBox("Monocypher", "Enter password to cipher")
If Not $sPassword Then Exit

$bCipher = _MC_Lock($sPlainData, _MC_Blake2b($sPassword, 32), $bNonce, $bMac)

ConsoleWrite("> Locked" & @CRLF & _
	@TAB & "Cipher: " & $bCipher & @CRLF & _
	@TAB & "Nonce:  " & $bNonce & @CRLF & _
	@TAB & "MAC:    " & $bMac & @CRLF)

; unlock
$sPassword = InputBox("Monocypher", "Enter password to decipher")
If Not $sPassword Then Exit

$bClear = _MC_Unlock($bCipher, _MC_Blake2b($sPassword, 32), $bNonce, $bMac)
If @error Then
	ConsoleWrite("! Bad decipher key" & @CRLF)
Else
	ConsoleWrite("> Unlocked: " & BinaryToString($bClear, 4) & @CRLF)
EndIf

#EndRegion
