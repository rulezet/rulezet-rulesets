rule Backdoor_BAT_XenoRat_BSA_MTB_2{
	meta:
		description = "Backdoor:BAT/XenoRat.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 65 6e 6f 20 72 61 74 20 63 6c 69 65 6e 74 } 		$a_01_1 = {78 65 6e 6f 5f 72 61 74 5f 63 6c 69 65 6e 74 } 		$a_01_2 = {5c 78 65 6e 6f 2d 72 61 74 5c 50 6c 75 67 69 6e 73 } 		$a_01_3 = {53 65 6e 64 41 73 79 6e 63 } 		$a_01_4 = {49 41 73 79 6e 63 53 74 61 74 65 4d 61 63 68 69 6e 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*6+(#a_01_4  & 1)*6) >=22
 
}