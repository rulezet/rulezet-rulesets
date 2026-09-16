rule Trojan_AndroidOS_Rewardsteal_N{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.N,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 61 72 6d 66 75 6c 41 70 70 52 65 63 65 69 76 65 72 } 		$a_01_1 = {70 61 6b 61 2f 70 6f 2f 54 68 61 6e 6b } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}