rule Trojan_BAT_ZgRAT_B_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 48 48 62 48 38 37 2e 67 2e 72 65 73 6f 75 72 63 65 73 } 		$a_01_1 = {42 48 48 62 48 38 37 2e 70 64 62 } 		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_01_3 = {47 65 74 54 79 70 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}