rule Trojan_BAT_Heracles_ARR_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_03_0 = {16 31 0a 12 00 28 ?? ?? ?? ?? 16 30 5c 1f 18 18 73 ?? ?? ?? ?? 13 08 12 08 } 		$a_03_1 = {18 5b 0c 12 00 28 ?? ?? ?? ?? 18 5b 0d 08 09 73 ?? ?? ?? ?? 13 04 11 04 } 		$a_81_2 = {3c 53 65 74 52 65 6d 6f 74 65 43 6c 69 70 62 6f 61 72 64 3e 62 5f 5f 30 } 		$a_81_3 = {3c 64 65 70 6c 6f 79 6d 65 6e 74 49 64 3e 35 5f 5f 34 } 	condition:
		((#a_03_0  & 1)*11+(#a_03_1  & 1)*9+(#a_81_2  & 1)*6+(#a_81_3  & 1)*4) >=30
 
}