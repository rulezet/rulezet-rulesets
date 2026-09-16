rule Trojan_Linux_WellMess_A_MTB{
	meta:
		description = "Trojan:Linux/WellMess.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {43 3a 2f 53 65 72 76 65 72 2f 42 6f 74 55 49 2f 41 70 70 5f 44 61 74 61 2f 54 65 6d 70 2f [0-20] 2f 73 72 63 2f [0-20] 2e 67 6f 00 00 } 		$a_00_1 = {72 75 6e 74 69 6d 65 2e 69 6e 6a 65 63 74 67 6c 69 73 74 } 		$a_00_2 = {2e 68 69 6a 61 63 6b 65 64 } 	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}