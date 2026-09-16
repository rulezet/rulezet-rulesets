rule PWS_Win32_Frethog_MR{
	meta:
		description = "PWS:Win32/Frethog.MR,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 07 00 06 00 00 "
		
	strings :
		$a_03_0 = {78 f8 ff ff e9 90 09 0d 00 2b ?? 83 ?? 05 89 ?? 74 f8 ff ff c6 85 } 		$a_01_1 = {c7 85 70 f8 ff ff 20 00 00 e0 } 		$a_01_2 = {b8 64 6c 6c 00 } 		$a_01_3 = {68 64 6c 6c 00 } 		$a_01_4 = {25 73 5c 77 69 6e 5f 25 64 2e 6c 6f 67 00 } 		$a_01_5 = {49 44 52 5f 44 4c 4c 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}