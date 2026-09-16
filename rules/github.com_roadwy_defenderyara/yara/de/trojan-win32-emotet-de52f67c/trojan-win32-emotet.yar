rule Trojan_Win32_Emotet{
	meta:
		description = "Trojan:Win32/Emotet,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 6b 44 5a 32 49 56 75 4f 5f 71 6f 70 2e 70 64 62 } 		$a_02_1 = {8b 74 24 04 8a 1c 31 2a 1c 15 ?? ?? ?? ?? 8b 54 24 ?? 88 1c 32 83 c6 33 } 		$a_02_2 = {89 45 d8 31 d2 f7 f1 8b 4d e8 8b 75 d8 8a 1c 31 2a 1c 15 ?? ?? ?? ?? 8b 55 e4 88 1c 32 83 c6 33 } 	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}