rule Trojan_BAT_DuckTail_ADU_MTB{
	meta:
		description = "Trojan:BAT/DuckTail.ADU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 16 13 05 38 ?? 00 00 00 11 04 11 05 9a 28 ?? 00 00 0a 13 06 11 06 72 ?? 01 00 70 6f ?? 00 00 0a 2d 0e 11 06 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}