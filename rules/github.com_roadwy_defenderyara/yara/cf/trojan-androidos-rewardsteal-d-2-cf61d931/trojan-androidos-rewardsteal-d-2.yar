rule Trojan_AndroidOS_Rewardsteal_D_2{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.D,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 69 63 69 63 69 2f 6f 74 70 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 24 62 69 6e 64 57 65 62 24 32 } 		$a_01_1 = {6c 65 74 2d 46 6f 72 6d 41 63 74 69 76 69 74 79 24 66 65 74 63 68 53 4d 53 4d 65 73 73 61 67 65 73 24 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}