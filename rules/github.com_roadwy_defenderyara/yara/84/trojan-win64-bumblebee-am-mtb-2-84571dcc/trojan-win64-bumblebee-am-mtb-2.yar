rule Trojan_Win64_BumbleBee_AM_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 61 6d 70 20 66 61 72 72 69 65 72 } 		$a_01_1 = {63 75 72 6c 20 73 74 65 72 6e } 		$a_01_2 = {6a 61 7a 7a 20 6e 61 70 6f 6c 65 6f 6e } 		$a_01_3 = {6a 70 48 67 45 63 74 4f 4f 50 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}