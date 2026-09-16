rule Trojan_Win64_BumbleBee_AN_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 4b 75 45 4e 70 68 41 78 4e } 		$a_01_1 = {43 72 65 61 74 65 46 69 62 65 72 } 		$a_01_2 = {48 65 61 70 52 65 41 6c 6c 6f 63 } 		$a_01_3 = {53 65 74 53 74 64 48 61 6e 64 6c 65 } 		$a_01_4 = {53 65 74 46 69 6c 65 50 6f 69 6e 74 65 72 45 78 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}