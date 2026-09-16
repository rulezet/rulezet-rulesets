rule Trojan_BAT_AveMaria_ABS_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {04 06 91 20 ?? ?? ?? 00 59 d2 9c 00 06 17 58 0a 06 7e 03 ?? ?? 04 8e 69 fe 04 0b 07 2d d7 7e 03 ?? ?? 04 0c 2b 00 08 2a 90 0a 32 00 7e 03 ?? ?? 04 06 7e 03 } 		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 		$a_01_3 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}