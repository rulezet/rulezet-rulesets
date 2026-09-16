rule Trojan_AndroidOS_Rewardsteal_HT_2{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.HT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 6c 65 61 73 65 20 45 6e 74 65 72 20 41 76 61 69 6c 61 62 6c 65 20 4c 69 6d 69 74 20 6f 66 20 43 61 72 64 } 		$a_01_1 = {69 6e 73 65 72 74 4d 73 67 64 61 74 61 3a 20 6d 61 73 73 61 67 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}