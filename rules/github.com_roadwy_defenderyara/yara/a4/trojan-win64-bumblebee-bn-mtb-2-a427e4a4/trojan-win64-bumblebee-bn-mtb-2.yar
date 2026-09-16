rule Trojan_Win64_BumbleBee_BN_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 69 59 57 39 33 39 35 46 } 		$a_01_1 = {4f 69 67 66 78 30 77 38 } 		$a_01_2 = {55 48 70 77 6a 75 33 33 34 36 4e 56 } 		$a_01_3 = {50 6a 79 4a 47 47 43 76 51 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}