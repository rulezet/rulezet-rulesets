rule Trojan_AndroidOS_Rewardsteal_Q_2{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.Q,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 65 62 2f 61 70 69 2f 75 73 65 72 2f 73 6d 73 } 		$a_00_1 = {61 70 69 2f 75 73 65 72 2f 73 74 65 70 31 } 		$a_00_2 = {54 71 41 63 74 69 76 69 74 79 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}