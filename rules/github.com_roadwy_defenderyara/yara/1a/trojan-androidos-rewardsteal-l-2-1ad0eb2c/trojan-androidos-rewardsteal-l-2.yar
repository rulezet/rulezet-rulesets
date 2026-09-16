rule Trojan_AndroidOS_Rewardsteal_L_2{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.L,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 6d 61 6b 65 77 69 6e 6c 6f 76 65 2e 69 6e 2f } 		$a_01_1 = {43 61 72 64 20 43 56 56 20 69 73 20 52 65 71 75 69 72 65 64 20 21 } 		$a_01_2 = {4c 63 6f 6d 2f 73 75 70 65 72 63 65 6c 6c 2f 63 6c 61 73 68 6f 66 63 6c 61 6e 2f 54 71 41 63 74 69 76 69 74 79 3b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}