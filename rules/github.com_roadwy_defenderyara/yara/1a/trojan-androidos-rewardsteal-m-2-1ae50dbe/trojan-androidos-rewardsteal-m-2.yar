rule Trojan_AndroidOS_Rewardsteal_M_2{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.M,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 65 6c 63 6f 6d 65 5f 74 6f 5f 72 65 77 61 72 64 73 5f 70 6f 69 6e 74 73 5f 6e 65 72 5f 62 61 6e 6b 69 6e 67 5f 6c 6f 67 69 6e } 		$a_01_1 = {72 65 67 69 73 74 65 72 64 5f 6d 6f 62 69 6c 65 5f 6e 6f 5f 63 75 73 74 6f 6d 65 72 5f 69 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}