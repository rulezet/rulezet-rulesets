rule Trojan_BAT_Lummac_PGL_MTB{
	meta:
		description = "Trojan:BAT/Lummac.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 07 1f 28 5a 58 13 08 28 ?? 00 00 0a 07 11 08 1e 6f ?? 00 00 0a 17 8d ?? 00 00 01 6f ?? 00 00 0a 13 09 11 09 28 ?? 00 00 0a 72 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}