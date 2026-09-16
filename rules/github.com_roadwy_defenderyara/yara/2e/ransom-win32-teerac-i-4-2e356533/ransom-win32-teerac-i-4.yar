rule Ransom_Win32_Teerac_I__4{
	meta:
		description = "Ransom:Win32/Teerac.I!!Teerac.I,SIGNATURE_TYPE_ARHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 2e 5c 2e 2e 5c 73 6f 75 72 63 65 73 5c 65 78 74 2d 6c 69 62 73 5c 6c 69 62 74 6f 6d 63 72 79 70 74 5c 63 69 70 68 65 72 73 5c 61 65 73 } 		$a_01_1 = {65 79 75 69 6f 61 } 		$a_01_2 = {71 77 72 74 70 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}