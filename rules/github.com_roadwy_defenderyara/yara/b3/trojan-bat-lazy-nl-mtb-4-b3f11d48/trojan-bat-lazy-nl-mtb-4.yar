rule Trojan_BAT_Lazy_NL_MTB_4{
	meta:
		description = "Trojan:BAT/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 41 01 00 70 13 0b 11 05 72 fe 01 00 70 72 41 01 00 70 6f 27 00 00 0a 13 0c 11 07 16 fe 04 16 fe 01 13 0d 11 0d 2c 3b 00 02 7b 0c 00 00 04 } 		$a_01_1 = {72 e5 02 00 70 72 e0 01 00 70 28 23 00 00 0a 26 20 ee 02 00 00 28 03 00 00 0a 00 72 0f 03 00 70 28 35 00 00 0a } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}