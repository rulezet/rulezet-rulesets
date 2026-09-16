rule Trojan_BAT_Formbook_RS_MTB_4{
	meta:
		description = "Trojan:BAT/Formbook.RS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 08 09 28 34 00 00 06 28 32 00 00 06 00 28 31 00 00 06 28 33 00 00 06 28 30 00 00 06 00 17 13 04 00 28 2f 00 00 06 d2 06 28 2d 00 00 06 00 00 00 09 17 58 0d 09 17 fe 04 13 05 11 05 2d c0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}