rule Trojan_BAT_Formbook_RS_MTB_3{
	meta:
		description = "Trojan:BAT/Formbook.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 90 00 00 0a 28 8d 00 00 0a 16 16 11 09 11 08 18 28 99 00 00 06 28 8d 00 00 0a 18 28 99 00 00 06 28 91 00 00 0a 8c 59 00 00 01 a2 14 28 92 00 00 0a 1e } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}