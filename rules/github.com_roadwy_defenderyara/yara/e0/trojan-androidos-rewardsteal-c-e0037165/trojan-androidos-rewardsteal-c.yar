rule Trojan_AndroidOS_Rewardsteal_C{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.C,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 61 6e 61 72 72 61 35 34 35 2d 64 65 66 61 75 6c 74 2d 72 74 64 62 2e 66 69 72 65 62 61 73 65 69 6f 2e 63 6f 6d 2f } 		$a_01_1 = {50 6c 65 61 73 65 20 57 61 69 74 20 32 34 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}