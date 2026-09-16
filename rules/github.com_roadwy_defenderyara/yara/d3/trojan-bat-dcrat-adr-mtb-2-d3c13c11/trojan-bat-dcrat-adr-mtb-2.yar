rule Trojan_BAT_DCRat_ADR_MTB_2{
	meta:
		description = "Trojan:BAT/DCRat.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 29 07 06 08 16 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 05 12 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 11 04 17 58 13 04 11 04 09 fe 04 13 06 11 06 2d cc } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}