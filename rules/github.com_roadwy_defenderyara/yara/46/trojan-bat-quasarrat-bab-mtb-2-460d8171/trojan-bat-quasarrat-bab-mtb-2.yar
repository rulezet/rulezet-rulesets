rule Trojan_BAT_QuasarRAT_BAB_MTB_2{
	meta:
		description = "Trojan:BAT/QuasarRAT.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 06 11 06 06 11 06 91 66 d2 9c 06 11 06 06 11 06 91 19 63 06 11 06 91 1b 62 60 d2 9c 06 11 06 06 11 06 91 11 05 11 06 11 05 8e 69 5d 91 61 d2 9c 00 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 08 11 08 2d bb } 		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_01_2 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}