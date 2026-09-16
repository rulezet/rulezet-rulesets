rule Trojan_Win64_BumbleBee_AM_MTB_3{
	meta:
		description = "Trojan:Win64/BumbleBee.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 57 48 77 79 36 52 } 		$a_01_1 = {6c 46 4a 55 4e 6b 78 47 68 4c } 		$a_01_2 = {53 65 74 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 41 } 		$a_01_3 = {75 67 67 79 20 72 65 63 6f 76 65 72 20 70 6f 6c 69 74 65 6e 65 73 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}