rule Trojan_BAT_Formbook_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 8e 69 5d 13 08 09 11 08 91 13 09 11 06 17 58 08 5d } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}