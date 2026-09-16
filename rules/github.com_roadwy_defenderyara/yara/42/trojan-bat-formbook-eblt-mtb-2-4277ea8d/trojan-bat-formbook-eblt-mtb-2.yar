rule Trojan_BAT_Formbook_EBLT_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.EBLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 06 11 1c 1f 61 5a 61 13 1d 00 02 11 1b 11 1c ?? ?? ?? ?? ?? 13 1e 04 03 ?? ?? ?? ?? ?? 59 13 1f 11 1f 13 20 11 20 19 fe 02 13 26 11 26 2c 03 19 13 20 11 20 16 fe 04 13 27 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}