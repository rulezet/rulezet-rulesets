rule Backdoor_Win32_Kriskynote_A_2{
	meta:
		description = "Backdoor:Win32/Kriskynote.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {f7 de 83 f8 01 75 1d 33 c0 85 f6 7e 17 8a 4c 24 13 8a 14 28 32 d1 fe c1 88 14 28 40 3b c6 88 4c 24 13 7c e9 57 ff 15 } 		$a_11_1 = {00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 4e 00 74 00 55 00 73 00 65 00 72 00 45 00 78 00 01 } 		$a_8a_2 = {31 } 	condition:
		((#a_01_0  & 1)*2+(#a_11_1  & 1)*1+(#a_8a_2  & 1)*5376) >=3
 
}