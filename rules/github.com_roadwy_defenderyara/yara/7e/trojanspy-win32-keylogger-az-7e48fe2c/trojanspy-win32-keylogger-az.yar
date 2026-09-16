rule TrojanSpy_Win32_Keylogger_AZ{
	meta:
		description = "TrojanSpy:Win32/Keylogger.AZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-09] 2e 65 78 65 [0-09] 25 32 30 00 47 45 54 20 2f 6c 6f 61 64 64 64 2e 70 68 70 } 		$a_00_1 = {6b 65 79 6c 6f 67 67 65 72 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}