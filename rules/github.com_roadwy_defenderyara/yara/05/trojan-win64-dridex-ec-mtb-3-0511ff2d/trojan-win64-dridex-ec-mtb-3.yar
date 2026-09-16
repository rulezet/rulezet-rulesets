rule Trojan_Win64_Dridex_EC_MTB_3{
	meta:
		description = "Trojan:Win64/Dridex.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {72 72 70 69 6f 64 65 2e 70 64 62 } 		$a_81_1 = {47 65 74 4e 4c 53 56 65 72 73 69 6f 6e } 		$a_81_2 = {49 63 6d 70 53 65 6e 64 45 63 68 6f 32 } 		$a_81_3 = {6d 61 6c 6c 6f 63 } 		$a_81_4 = {4f 4c 45 41 55 54 33 32 2e 64 6c 6c } 		$a_81_5 = {47 65 74 4c 61 73 74 45 72 72 6f 72 } 	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}