rule Trojan_BAT_Formbook_EHLS_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EHLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 08 11 13 1f 3d 5a 61 13 14 00 02 11 12 11 13 ?? ?? ?? ?? ?? 13 15 04 03 ?? ?? ?? ?? ?? 59 13 16 11 16 13 17 11 17 19 fe 02 13 1d 11 1d 2c 03 19 13 17 11 17 16 fe 04 13 1e 11 1e 2c 03 16 13 17 11 08 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}