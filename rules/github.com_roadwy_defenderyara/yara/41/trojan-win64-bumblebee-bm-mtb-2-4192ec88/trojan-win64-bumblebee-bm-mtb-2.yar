rule Trojan_Win64_BumbleBee_BM_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 57 59 37 32 } 		$a_01_1 = {51 43 59 5a 6e 36 37 34 37 48 } 		$a_01_2 = {51 4f 55 58 49 33 31 } 		$a_01_3 = {52 6f 4f 45 69 7a 74 4a 76 57 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}