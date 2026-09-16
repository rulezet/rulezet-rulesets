rule Trojan_AndroidOS_Rewardsteal_HT{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.HT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 6c 65 61 73 65 20 66 69 6c 6c 20 50 41 53 53 57 4f 52 44 } 		$a_01_1 = {50 6c 65 61 73 65 20 66 69 6c 6c 20 65 78 70 61 72 79 20 64 61 74 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}