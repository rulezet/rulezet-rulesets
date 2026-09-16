rule Trojan_Linux_Stiniter_A{
	meta:
		description = "Trojan:Linux/Stiniter.A,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 64 61 74 61 2f 6c 6f 67 2e 74 78 74 } 		$a_01_1 = {2f 64 61 74 61 2f 72 65 6e 64 } 		$a_01_2 = {2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65 00 00 2f 00 00 00 70 69 70 65 43 6d 64 3a 3c 25 73 3e } 		$a_01_3 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 6b 65 65 70 65 72 } 		$a_01_4 = {72 65 61 64 20 66 64 20 69 73 73 65 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}