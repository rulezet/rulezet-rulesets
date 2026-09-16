rule Trojan_BAT_Formbook_AOK_MTB_3{
	meta:
		description = "Trojan:BAT/Formbook.AOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 11 00 02 03 06 04 05 28 ?? 00 00 06 00 06 17 58 0a 00 06 02 6f ?? 00 00 0a 2f 0b 04 6f ?? 00 00 0a 05 fe 04 2b 01 16 0b 07 2d d6 } 		$a_03_1 = {02 03 04 6f ?? 00 00 0a 0a 0e 04 05 6f ?? 00 00 0a 59 0b 06 07 05 28 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}