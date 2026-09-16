rule Trojan_Win32_Meterpreter_A__39{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 31 db 53 53 53 53 53 68 3a 56 79 a7 ff d5 } 		$a_01_1 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 } 		$a_01_2 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb } 		$a_03_3 = {68 2d 06 18 7b ff d5 85 c0 75 ?? 68 88 13 00 00 68 44 f0 35 e0 ff d5 4f 75 } 		$a_03_4 = {53 56 68 12 96 89 e2 ff d5 85 c0 74 ?? 8b 07 01 c3 85 c0 75 } 		$a_03_5 = {68 2d 06 18 7b ff d5 85 c0 75 [0-20] 68 58 a4 53 e5 ff d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}