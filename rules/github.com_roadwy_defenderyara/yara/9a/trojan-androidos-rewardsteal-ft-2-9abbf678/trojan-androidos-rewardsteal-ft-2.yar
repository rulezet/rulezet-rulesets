rule Trojan_AndroidOS_Rewardsteal_FT_2{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.FT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {69 64 66 63 2d 34 66 35 34 61 2d 64 65 66 61 75 6c 74 2d 72 74 64 62 2e 66 69 72 65 62 61 73 65 69 6f 2e 63 6f 6d } 		$a_00_1 = {73 74 75 64 65 6e 74 37 30 31 31 2e 67 69 74 68 75 62 2e 69 6f 2f 69 64 66 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}