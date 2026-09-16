rule Trojan_BAT_RevengeRat_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/RevengeRat.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 13 07 28 ?? 00 00 0a 0d 19 13 07 17 28 ?? 00 00 0a 1f 20 17 19 15 28 ?? 00 00 0a 1a 13 07 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 0a 1b 13 07 17 12 00 15 6a 16 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}