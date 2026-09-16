rule Trojan_BAT_Formbook_AMAA_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 ?? 07 11 ?? 02 07 11 ?? 91 11 ?? 61 07 11 ?? 91 59 28 ?? ?? 00 06 28 ?? ?? 00 ?? 9c [0-01] 11 ?? 17 58 13 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}