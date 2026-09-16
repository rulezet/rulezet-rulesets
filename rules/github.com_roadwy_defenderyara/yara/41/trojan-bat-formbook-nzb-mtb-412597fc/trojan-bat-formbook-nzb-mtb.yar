rule Trojan_BAT_Formbook_NZB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 06 18 d8 0a 06 07 fe 02 13 05 11 05 2c 02 07 0a 00 06 07 5d 16 } 		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 		$a_81_2 = {57 65 62 53 65 72 76 69 63 65 73 } 	condition:
		((#a_01_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=5
 
}