rule Trojan_BAT_RevengeRat_ART_MTB_2{
	meta:
		description = "Trojan:BAT/RevengeRat.ART!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0b 07 28 37 00 00 0a 3a 12 00 00 00 07 28 1d 00 00 06 28 38 00 00 0a 07 28 39 00 00 0a 26 07 28 37 00 00 0a 39 0e 00 00 00 07 18 28 3a 00 00 0a 07 28 39 00 00 0a 26 28 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}