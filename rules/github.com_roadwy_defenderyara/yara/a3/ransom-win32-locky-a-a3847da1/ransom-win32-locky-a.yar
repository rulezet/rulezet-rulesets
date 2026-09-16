rule Ransom_Win32_Locky_A{
	meta:
		description = "Ransom:Win32/Locky.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 fc 89 0c 24 8b 4d 08 8d 64 24 fc 33 0c 24 8b } 		$a_01_1 = {83 ec 04 89 0c 24 8b 4d 08 83 ec 04 33 0c 24 8b ff } 		$a_01_2 = {f4 69 63 6b 43 c7 45 f8 6f 75 6e 74 ff 15 0c 01 } 		$a_01_3 = {d8 8d 36 b9 00 00 00 00 f7 d8 f7 d8 8d 36 83 c9 } 		$a_01_4 = {d8 f7 d8 8d 36 6a ff 83 c9 ff f7 d8 f7 d8 8d 36 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}