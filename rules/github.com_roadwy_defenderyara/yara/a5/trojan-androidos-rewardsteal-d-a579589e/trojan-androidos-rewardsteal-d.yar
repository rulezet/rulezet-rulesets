rule Trojan_AndroidOS_Rewardsteal_D{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.D,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 46 69 65 6c 64 20 72 65 71 75 69 72 65 73 20 31 36 20 64 69 67 69 74 } 		$a_01_1 = {50 65 72 6d 69 73 69 69 6f 6e 65 52 65 71 75 65 73 74 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}