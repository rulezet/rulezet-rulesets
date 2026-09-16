rule Trojan_AndroidOS_Rewardsteal_M{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.M,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 6c 65 64 5f 48 61 69 } 		$a_01_1 = {44 41 54 41 5f 55 53 45 52 5f 4e 4f 57 } 		$a_01_2 = {73 65 6e 64 5f 66 69 6c 74 65 72 65 64 5f 73 6d 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}