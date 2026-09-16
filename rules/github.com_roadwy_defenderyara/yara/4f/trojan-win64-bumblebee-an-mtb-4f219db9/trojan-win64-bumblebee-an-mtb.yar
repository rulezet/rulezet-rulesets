rule Trojan_Win64_BumbleBee_AN_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {59 56 4b 30 37 37 63 } 		$a_01_1 = {5a 50 76 44 7a 4e 37 31 35 6e } 		$a_01_2 = {50 65 65 6b 4e 61 6d 65 64 50 69 70 65 } 		$a_01_3 = {47 65 74 53 74 64 48 61 6e 64 6c 65 } 		$a_01_4 = {43 72 65 61 74 65 46 69 6c 65 41 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}