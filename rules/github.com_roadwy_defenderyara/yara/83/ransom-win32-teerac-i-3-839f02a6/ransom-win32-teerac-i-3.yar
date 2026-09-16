rule Ransom_Win32_Teerac_I__3{
	meta:
		description = "Ransom:Win32/Teerac.I!!Teerac.I,SIGNATURE_TYPE_ARHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 6f 72 5c 74 6f 72 72 5c 6c 69 62 72 65 73 73 6c 2d 32 2e 33 2e 31 5c 73 73 6c 5c 73 73 6c 5f 6c 69 62 2e 63 } 		$a_01_1 = {65 79 75 69 6f 61 } 		$a_01_2 = {71 77 72 74 70 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}