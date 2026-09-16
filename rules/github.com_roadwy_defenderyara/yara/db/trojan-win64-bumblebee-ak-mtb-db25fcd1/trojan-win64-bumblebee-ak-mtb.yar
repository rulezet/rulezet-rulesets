rule Trojan_Win64_BumbleBee_AK_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 53 6f 68 30 35 49 71 36 } 		$a_01_1 = {50 7a 7a 44 34 36 39 52 30 } 		$a_01_2 = {72 69 62 20 67 6f 64 20 64 65 64 69 63 61 74 65 } 		$a_01_3 = {6b 6f 6e 72 61 64 20 72 65 70 61 69 72 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}