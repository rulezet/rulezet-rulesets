rule Trojan_Win32_Foosace_E_dha{
	meta:
		description = "Trojan:Win32/Foosace.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 45 08 6a 07 03 c7 33 d2 89 45 e0 8d 47 01 5b f7 f3 8a d9 6a 07 02 5d 0f 8a 04 32 33 d2 f6 eb 8a d8 8b c7 5f f7 f7 8b 7d f8 6a 07 8a 44 37 fe 02 45 fc 02 1c 32 b2 03 f6 ea 88 5d 13 8a d8 02 d9 8d 47 ff 33 d2 59 f7 f1 8a 4d 13 8b 45 e0 c0 e3 06 02 1c 32 32 cb 30 08 8b 4d 14 41 47 3b 4d e4 89 4d 14 89 7d f8 72 97 } 		$a_01_1 = {49 6e 69 74 31 } 		$a_80_2 = {37 30 2e 38 35 2e 32 32 31 2e 31 30 } 		$a_80_3 = {7e 78 68 2f 63 68 2e 63 67 69 } 	condition:
		((#a_00_0  & 1)*4+(#a_01_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=10
 
}