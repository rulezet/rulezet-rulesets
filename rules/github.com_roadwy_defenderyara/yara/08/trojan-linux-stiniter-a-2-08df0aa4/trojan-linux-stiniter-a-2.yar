rule Trojan_Linux_Stiniter_A_2{
	meta:
		description = "Trojan:Linux/Stiniter.A,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 67 6f 6f 67 6c 65 6d 65 73 73 61 67 65 2e 61 70 6b } 		$a_01_1 = {2f 61 6e 64 72 6f 69 64 2e 69 6e 66 6f } 		$a_01_2 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 61 6e 64 72 6f 69 64 2e 69 6e 66 6f } 		$a_01_3 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 6b 65 65 70 65 72 } 		$a_01_4 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 74 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}