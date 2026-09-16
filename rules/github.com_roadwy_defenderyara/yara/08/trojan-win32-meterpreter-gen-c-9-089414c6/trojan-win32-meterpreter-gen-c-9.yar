rule Trojan_Win32_Meterpreter_gen_C_9{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 } 		$a_01_1 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 } 		$a_01_2 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb } 		$a_03_3 = {68 58 a4 53 e5 ff d5 [0-10] 6a 00 56 53 57 68 02 d9 c8 5f ff d5 } 		$a_03_4 = {6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 ?? ff 4e 08 75 } 		$a_01_5 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 89 e8 ff d0 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 } 		$a_03_6 = {68 b7 e9 38 ff ff d5 [0-08] 68 74 ec 3b e1 ff d5 [0-08] 68 75 6e 4d 61 ff d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=5
 
}