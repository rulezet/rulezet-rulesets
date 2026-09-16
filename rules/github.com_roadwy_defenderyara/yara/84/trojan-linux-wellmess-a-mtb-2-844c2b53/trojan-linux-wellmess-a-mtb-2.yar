rule Trojan_Linux_WellMess_A_MTB_2{
	meta:
		description = "Trojan:Linux/WellMess.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 68 6f 6d 65 2f 75 62 75 6e 74 75 2f 47 6f 50 72 6f 6a 65 63 74 2f 73 72 63 2f 62 6f 74 2f 62 6f 74 6c 69 62 2e 77 65 6c 6c 4d 65 73 73 } 		$a_00_1 = {6d 61 69 6e 2e 67 65 74 49 50 } 		$a_00_2 = {62 6f 74 6c 69 62 2e 47 65 74 52 61 6e 64 6f 6d 42 79 74 65 73 } 		$a_00_3 = {2f 62 6f 74 2f 62 6f 74 6c 69 62 2e 53 65 6e 64 4d 65 73 73 61 67 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}