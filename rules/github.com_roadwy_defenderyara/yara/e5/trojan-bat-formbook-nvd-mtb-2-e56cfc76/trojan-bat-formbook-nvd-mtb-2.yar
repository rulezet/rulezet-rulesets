rule Trojan_BAT_Formbook_NVD_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.NVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 23 00 00 70 28 53 00 00 0a 0b 07 72 27 00 00 70 28 53 00 00 0a 0b 07 72 2b 00 00 70 28 53 00 00 0a 0b 07 72 17 00 00 70 28 53 00 00 0a 0b 07 72 2f 00 00 70 28 53 00 00 0a 0b 07 72 13 00 00 70 28 53 00 00 0a 0b 07 72 0f 00 00 70 28 53 00 00 0a 0b 07 72 33 00 00 70 28 53 00 00 0a 0b 07 72 37 00 00 70 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}