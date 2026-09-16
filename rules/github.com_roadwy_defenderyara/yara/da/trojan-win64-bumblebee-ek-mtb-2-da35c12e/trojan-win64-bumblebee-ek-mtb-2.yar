rule Trojan_Win64_BumbleBee_EK_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 6e 6d 7a 44 42 39 38 33 4f 38 6c } 		$a_01_1 = {4f 75 76 50 64 31 36 } 		$a_01_2 = {51 72 61 33 38 39 37 } 		$a_01_3 = {43 72 65 61 74 65 46 69 6c 65 57 } 		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}