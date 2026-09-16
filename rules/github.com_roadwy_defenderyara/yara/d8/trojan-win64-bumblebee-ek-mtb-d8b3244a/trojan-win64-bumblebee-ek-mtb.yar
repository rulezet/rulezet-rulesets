rule Trojan_Win64_BumbleBee_EK_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 41 6f 4e 32 30 34 37 } 		$a_01_1 = {51 5a 63 76 36 38 35 77 } 		$a_01_2 = {43 72 65 61 74 65 54 61 73 6b } 		$a_01_3 = {4c 6f 63 6b 46 69 6c 65 } 		$a_01_4 = {43 72 65 61 74 65 46 69 6c 65 57 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}