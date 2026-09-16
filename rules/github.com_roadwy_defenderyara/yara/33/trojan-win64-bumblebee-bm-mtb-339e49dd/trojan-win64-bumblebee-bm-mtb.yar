rule Trojan_Win64_BumbleBee_BM_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 6c 6f 4f 45 45 69 48 6a } 		$a_01_1 = {50 76 68 67 4f 71 } 		$a_01_2 = {4e 79 47 6c 69 73 44 49 4b 4e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}