rule Trojan_BAT_AgentTesla_ASDP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 08 8e 69 17 da 13 08 16 13 09 2b 23 09 11 09 17 8d ?? 00 00 01 25 16 08 11 09 9a 1f 10 28 ?? 00 00 0a 86 9c 6f ?? 00 00 0a 11 09 17 d6 13 09 11 09 11 08 31 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}