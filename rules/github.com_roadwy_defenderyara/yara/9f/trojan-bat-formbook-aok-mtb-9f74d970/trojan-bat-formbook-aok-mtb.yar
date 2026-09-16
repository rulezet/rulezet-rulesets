rule Trojan_BAT_Formbook_AOK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 1c 12 10 28 ?? ?? ?? 0a 0d 2b 12 12 10 28 ?? ?? ?? 0a 0d 2b 08 12 10 28 ?? ?? ?? 0a 0d 11 05 09 6f ?? ?? ?? 0a 08 17 58 0c 08 11 07 fe 04 13 0c 11 0c 2d a4 07 17 58 0b 07 11 08 fe 04 13 0d 11 0d 2d 91 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}