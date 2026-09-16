rule Trojan_Win64_BumbleBee_AK_MTB_3{
	meta:
		description = "Trojan:Win64/BumbleBee.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 78 68 55 4f 59 7a 66 61 63 } 		$a_01_1 = {72 61 6e 6b 20 77 69 74 68 6f 75 74 20 73 74 75 63 6b } 		$a_01_2 = {63 69 72 63 75 6c 61 72 20 6e 69 67 68 74 6d 61 72 65 20 67 61 6c 65 } 		$a_01_3 = {53 75 73 70 65 6e 64 54 68 72 65 61 64 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}