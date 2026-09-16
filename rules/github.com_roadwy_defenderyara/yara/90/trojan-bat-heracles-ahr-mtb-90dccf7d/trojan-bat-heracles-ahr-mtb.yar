rule Trojan_BAT_Heracles_AHR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 27 06 07 9a 25 6f ?? 00 00 0a 6f ?? 01 00 0a 80 3a 00 00 04 28 ?? 00 00 06 28 ?? 01 00 0a 16 28 ?? 00 00 0a 07 17 58 0b 07 06 8e 69 32 d3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}