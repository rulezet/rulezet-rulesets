rule Trojan_BAT_Agenttesla_PGAT_MTB_2{
	meta:
		description = "Trojan:BAT/Agenttesla.PGAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 1a 1f 11 5a 11 19 1f 1f 5a 58 11 0b 20 ?? ?? 00 00 6f ?? 00 00 0a 61 13 1b 11 19 1f 13 5a 11 1a 1f 17 5a 58 11 0b 20 ?? ?? 00 00 6f ?? 00 00 0a 61 13 1c 11 1a 11 19 61 20 ?? 00 00 00 5f 13 1d } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}