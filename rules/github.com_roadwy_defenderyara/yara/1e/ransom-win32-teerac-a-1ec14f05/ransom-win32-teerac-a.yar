rule Ransom_Win32_Teerac_A{
	meta:
		description = "Ransom:Win32/Teerac.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 1a 8d 53 fc 33 c9 8b c6 85 d2 74 0f 90 90 81 38 ef be ad de 74 29 41 40 3b ca 72 f2 } 		$a_03_1 = {8b 8b 28 02 00 00 8a 14 08 8b 4d fc 80 f2 ?? 88 14 01 40 3b 86 ?? ?? ?? ?? 72 e5 } 		$a_01_2 = {81 fb 41 50 33 32 75 0b 8b 5e 04 83 fb 18 } 		$a_01_3 = {ff d3 83 f8 ff 75 0a 6a 64 ff d7 46 83 fe 64 7c ef } 		$a_00_4 = {53 00 3a 00 28 00 4d 00 4c 00 3b 00 3b 00 4e 00 52 00 4e 00 57 00 4e 00 58 00 3b 00 3b 00 3b 00 4c 00 57 00 29 00 } 		$a_01_5 = {72 61 63 6b 65 74 65 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}