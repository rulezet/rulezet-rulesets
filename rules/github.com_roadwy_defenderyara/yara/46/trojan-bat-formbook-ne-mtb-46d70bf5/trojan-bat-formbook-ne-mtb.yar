rule Trojan_BAT_Formbook_NE_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 8e 69 5d 91 9c 00 11 04 17 58 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}