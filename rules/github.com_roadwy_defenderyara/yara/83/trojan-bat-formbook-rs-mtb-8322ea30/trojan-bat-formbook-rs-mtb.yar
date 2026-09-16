rule Trojan_BAT_Formbook_RS_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 06 09 06 09 8e 69 5d 91 08 06 91 61 d2 9c 06 17 58 0a 06 08 8e 69 32 e6 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}