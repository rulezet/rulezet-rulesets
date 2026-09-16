rule Trojan_BAT_Agenttesla_PGAT_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.PGAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 11 1c 11 0c 6f ?? ?? 00 0a 23 00 00 00 00 00 00 59 40 5a a1 11 09 11 1c 11 0c 6f ?? ?? 00 0a 23 00 00 00 00 00 00 24 40 5a 23 00 00 00 00 00 00 14 40 59 a1 11 1c 17 d6 13 1c 11 1c 11 1b 31 be } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}