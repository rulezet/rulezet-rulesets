rule Backdoor_Linux_Flosax_A{
	meta:
		description = "Backdoor:Linux/Flosax.A,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 61 70 70 6c 65 2e 6d 64 77 6f 72 6b 65 72 5f 73 65 72 76 65 72 } 		$a_01_1 = {7b 5f 78 70 63 5f 63 6f 6e 6e 65 63 74 69 6f 6e 5f 73 3d 7d } 		$a_01_2 = {72 65 61 64 4d 65 6d 6f 72 79 42 79 58 50 43 46 72 6f 6d 43 6f 6d 70 6f 6e 65 6e 74 3a 66 6f 72 41 67 65 6e 74 3a 77 69 74 68 43 6f 6d 6d 61 6e 64 54 79 70 65 3a } 		$a_01_3 = {78 70 63 5f 63 6f 6e 6e 65 63 74 69 6f 6e 5f 73 65 6e 64 5f 6d 65 73 73 61 67 65 5f 77 69 74 68 5f 72 65 70 6c 79 5f 73 79 6e 63 } 		$a_01_4 = {6d 58 70 63 43 6f 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}