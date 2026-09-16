rule Trojan_AndroidOS_Rewardsteal_N_2{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.N,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 78 70 69 72 79 20 73 68 6f 75 6c 64 20 62 65 20 61 74 6c 65 61 73 74 20 32 30 32 33 33 } 		$a_01_1 = {44 65 62 69 74 20 63 61 72 64 20 6e 6f 74 20 63 6f 72 72 65 63 74 65 64 } 		$a_01_2 = {46 6f 75 72 74 68 50 61 67 65 6d 28 64 65 62 69 74 3d } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}