rule Trojan_AndroidOS_Rewardsteal_Q{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.Q,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 69 63 69 63 69 62 61 6e 6b } 		$a_01_1 = {6d 65 73 73 61 67 65 20 20 6e 6f 74 20 73 65 6e 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}