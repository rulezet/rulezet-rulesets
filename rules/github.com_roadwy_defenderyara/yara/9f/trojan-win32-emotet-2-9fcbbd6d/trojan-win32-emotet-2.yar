rule Trojan_Win32_Emotet_2{
	meta:
		description = "Trojan:Win32/Emotet,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {c1 ea 04 6b c2 32 f7 d8 } 		$a_02_1 = {8b 7c 24 04 8a 9c 07 ?? ?? ?? ?? 89 74 24 38 89 54 24 3c 8b 44 24 18 8a 3c 08 28 df 8b 54 24 1c 88 3c 0a 83 c1 33 } 		$a_02_2 = {8b 4c 24 04 8a 9c 01 ?? ?? ?? ?? 8b 44 24 1c 8a 3c 08 28 df 8b 54 24 18 88 3c 0a 83 c1 33 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}