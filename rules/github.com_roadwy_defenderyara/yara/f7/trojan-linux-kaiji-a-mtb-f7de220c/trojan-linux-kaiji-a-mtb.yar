rule Trojan_Linux_Kaiji_A_MTB{
	meta:
		description = "Trojan:Linux/Kaiji.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6e 2e 41 6c 6c 6f 77 6c 69 73 74 } 		$a_00_1 = {2e 52 4e 47 } 		$a_00_2 = {66 61 6b 65 4c 6f 63 6b 65 72 } 		$a_00_3 = {4b 65 79 4c 6f 67 57 72 69 74 65 72 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}