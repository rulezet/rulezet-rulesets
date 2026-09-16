rule Trojan_Win64_BumbleBee_BN_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 63 71 61 37 35 } 		$a_01_1 = {51 45 70 7a 4b 62 36 } 		$a_01_2 = {55 7a 64 75 55 4f 74 52 5a 42 } 		$a_01_3 = {43 61 6c 6c 4e 61 6d 65 64 50 69 70 65 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}