rule Trojan_Win64_BumbleBee_BM_MTB_3{
	meta:
		description = "Trojan:Win64/BumbleBee.BM!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 4c 41 49 33 } 		$a_01_1 = {47 48 6a 61 63 75 64 52 } 		$a_01_2 = {47 78 42 6c 4f 4f } 		$a_01_3 = {53 65 74 56 50 41 43 6f 6e } 		$a_01_4 = {59 43 6c 68 6a 36 33 34 66 78 67 7a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1) >=9
 
}