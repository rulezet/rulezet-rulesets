rule Trojan_BAT_Formbook_RPG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 07 09 07 8e 69 5d 91 06 09 91 61 d2 9c 09 13 04 11 04 17 58 0d 09 06 8e 69 32 e3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}