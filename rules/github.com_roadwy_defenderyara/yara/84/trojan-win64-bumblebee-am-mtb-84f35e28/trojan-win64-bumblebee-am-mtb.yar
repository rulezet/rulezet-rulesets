rule Trojan_Win64_BumbleBee_AM_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 65 69 31 35 69 } 		$a_01_1 = {4c 69 52 4e 4e 35 46 } 		$a_01_2 = {58 5a 72 45 58 39 32 32 36 31 } 		$a_01_3 = {64 6f 6c 6c 73 20 74 68 65 6d 20 73 63 69 65 6e 74 69 66 69 63 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}