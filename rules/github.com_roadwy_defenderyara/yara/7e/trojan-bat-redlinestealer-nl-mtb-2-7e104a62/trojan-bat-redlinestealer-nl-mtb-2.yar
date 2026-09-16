rule Trojan_BAT_RedLineStealer_NL_MTB_2{
	meta:
		description = "Trojan:BAT/RedLineStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 02 06 8f 3f ?? ?? ?? 25 4b 03 06 95 61 54 00 06 17 59 0a 06 16 fe 04 16 fe 01 0b 07 } 		$a_03_1 = {00 02 06 8f 2d ?? ?? ?? 25 47 03 06 91 61 d2 52 00 06 17 59 0a 06 16 fe 04 16 fe 01 0b 07 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}