rule Trojan_Win64_BumbleBee_AG_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 66 72 30 37 41 37 34 } 		$a_01_1 = {51 58 59 75 6f 6b 36 36 30 } 		$a_01_2 = {71 75 42 6f 4e 53 6d 54 53 6c } 		$a_01_3 = {43 6f 6e 6e 65 63 74 4e 61 6d 65 64 50 69 70 65 } 		$a_01_4 = {44 69 73 63 6f 6e 6e 65 63 74 4e 61 6d 65 64 50 69 70 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}