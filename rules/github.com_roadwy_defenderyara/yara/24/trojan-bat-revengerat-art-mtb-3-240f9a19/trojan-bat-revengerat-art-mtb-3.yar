rule Trojan_BAT_RevengeRat_ART_MTB_3{
	meta:
		description = "Trojan:BAT/RevengeRat.ART!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 fe 01 13 07 11 07 2c 02 17 0c 03 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 09 02 11 05 17 28 ?? 00 00 0a 28 ?? 00 00 0a 06 07 d8 da 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 08 17 d6 0c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}