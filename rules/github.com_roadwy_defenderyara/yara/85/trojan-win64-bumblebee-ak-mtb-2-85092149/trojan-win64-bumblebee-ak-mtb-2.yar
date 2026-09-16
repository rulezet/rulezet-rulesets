rule Trojan_Win64_BumbleBee_AK_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 58 49 30 37 33 42 79 7a } 		$a_01_1 = {45 64 48 56 6e 74 71 64 57 74 } 		$a_01_2 = {50 65 65 6b 4e 61 6d 65 64 50 69 70 65 } 		$a_01_3 = {48 65 61 70 57 61 6c 6b } 		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}