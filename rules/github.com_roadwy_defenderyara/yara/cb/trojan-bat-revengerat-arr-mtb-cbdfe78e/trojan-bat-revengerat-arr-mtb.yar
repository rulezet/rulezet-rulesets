rule Trojan_BAT_RevengeRat_ARR_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0c 08 16 02 7b ?? 00 00 04 28 ?? 00 00 0a a2 08 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}