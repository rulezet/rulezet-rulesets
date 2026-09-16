rule Trojan_BAT_Formbook_AFN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 8e 69 8d ?? ?? ?? 01 0c 16 0a 2b 12 08 06 07 06 9a 1f 10 28 ?? ?? ?? 0a d2 9c 06 17 58 0a 06 07 8e 69 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}