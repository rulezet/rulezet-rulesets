rule Trojan_BAT_Formbook_EBLT_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EBLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 08 11 06 8e 69 17 da 13 0a 16 13 07 2b 15 11 08 11 07 11 06 11 07 9a ?? ?? ?? ?? ?? 00 11 07 17 d6 13 07 11 07 11 0a 31 e5 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}