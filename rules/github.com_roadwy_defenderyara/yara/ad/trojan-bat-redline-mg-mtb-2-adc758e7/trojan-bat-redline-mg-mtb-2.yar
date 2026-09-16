rule Trojan_BAT_Redline_MG_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {06 7e 29 00 00 04 06 91 20 34 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e 29 00 00 04 8e 69 fe 04 0b 07 2d d7 } 		$a_01_1 = {49 4a 4f 41 46 49 46 48 } 		$a_01_2 = {49 4a 55 41 44 46 57 46 } 		$a_01_3 = {62 61 7a 61 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}