rule Trojan_BAT_Heracles_AHR_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.AHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 07 11 09 11 07 17 28 ?? 00 00 06 28 ?? 00 00 06 12 00 20 d0 07 00 00 11 05 1d 1f 0b 6f ?? 00 00 0a d6 11 05 17 1f 0a 6f ?? 00 00 0a 11 05 17 1f 1e 6f ?? 00 00 0a 28 ?? 00 00 0a 11 09 06 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}