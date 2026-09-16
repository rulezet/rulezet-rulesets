rule Trojan_Win64_BumbleBee_AG_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 46 57 6b 52 54 46 77 6a 6d } 		$a_01_1 = {61 6e 74 20 62 65 61 72 69 6e 67 } 		$a_01_2 = {72 61 6e 73 6f 6d 20 74 72 65 61 63 68 65 72 6f 75 73 } 		$a_01_3 = {53 77 69 74 63 68 54 6f 46 69 62 65 72 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}