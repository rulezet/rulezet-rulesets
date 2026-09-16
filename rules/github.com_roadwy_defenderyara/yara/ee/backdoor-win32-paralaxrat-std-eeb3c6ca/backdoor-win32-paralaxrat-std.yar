rule Backdoor_Win32_ParalaxRat_STD{
	meta:
		description = "Backdoor:Win32/ParalaxRat.STD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 63 6f 46 47 2f 47 37 72 32 6b 34 } 		$a_01_1 = {34 44 35 41 36 42 36 35 37 32 36 45 36 35 36 43 33 33 33 32 30 30 30 30 35 30 34 35 } 		$a_01_2 = {3c 62 6c 6f 63 6b 32 3e 30 3c 2f 62 6c 6f 63 6b 32 3e } 		$a_01_3 = {78 6d 72 5f 6d 69 6e 65 5f 73 74 6f 70 } 		$a_01_4 = {72 65 6d 6f 74 65 62 72 6f 77 73 65 72 5f 69 6e 66 6f } 		$a_01_5 = {4b 45 59 4c 4f 47 3a 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}