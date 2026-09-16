rule Ransom_Win32_Cerber_A_{
	meta:
		description = "Ransom:Win32/Cerber.A!!Cerber.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 65 72 62 65 72 00 } 		$a_00_1 = {63 72 79 70 74 69 6d 70 6f 72 74 70 75 62 6c 69 63 6b 65 79 69 6e 66 6f } 		$a_00_2 = {63 72 79 70 74 65 6e 63 72 79 70 74 } 		$a_01_3 = {0f b6 f0 83 fe 66 7f 30 74 25 83 fe 26 74 17 83 fe 2e 74 12 83 fe 36 74 0d 83 fe 3e 74 08 83 c6 9c 83 fe 01 } 		$a_00_4 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8 } 	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*2+(#a_00_4  & 1)*2) >=8
 
}