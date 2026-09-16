rule Trojan_BAT_Formbook_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 04 05 28 ?? 00 00 06 0a 0e ?? 03 6f ?? 00 00 0a 59 0b 03 06 07 28 ?? 00 00 06 2a } 		$a_01_1 = {4c 00 6f 00 61 00 64 00 00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}