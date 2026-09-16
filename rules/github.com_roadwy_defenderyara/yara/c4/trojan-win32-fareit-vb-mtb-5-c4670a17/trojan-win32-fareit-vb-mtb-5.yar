rule Trojan_Win32_Fareit_VB_MTB_5{
	meta:
		description = "Trojan:Win32/Fareit.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {4b 61 77 61 69 69 2d 55 6e 69 63 6f 72 6e 2e 65 78 65 } 		$a_81_1 = {63 6d 64 20 2f 63 20 72 65 6e 61 6d 65 } 		$a_81_2 = {44 6c 6c 46 75 6e 63 74 69 6f 6e 43 61 6c 6c } 		$a_81_3 = {49 27 6d 20 55 6e 69 63 6f 72 6e } 		$a_81_4 = {5c 55 6e 69 63 6f 72 6e } 		$a_81_5 = {56 42 2e 43 6c 69 70 62 6f 61 72 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}