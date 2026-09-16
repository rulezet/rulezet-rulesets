rule Trojan_BAT_RevengeRat_ARA_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 0a 03 06 17 28 ?? 00 00 0a 28 ?? 00 00 0a 13 05 07 02 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 11 05 09 d8 da 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 06 17 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}