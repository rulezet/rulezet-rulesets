rule TrojanSpy_Win32_Keylogger_FR{
	meta:
		description = "TrojanSpy:Win32/Keylogger.FR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff ff 57 c6 85 ?? (fe|ff) ff ff 54 c6 85 ?? (fe|ff) ff ff 53 c6 85 ?? (fe|ff) ff ff 47 } 		$a_03_1 = {4a 79 05 ba 18 00 00 00 8a 44 ?? ?? 8a 1c 31 32 d8 88 1c 31 41 3b cf 7c e7 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}