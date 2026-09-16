rule Trojan_BAT_AgentTesla_GAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 0b 16 0a 2b 3b 16 0a 2b 1b 08 07 06 6f ?? 00 00 0a 13 09 09 12 09 28 ?? 00 00 0a 6f ?? 00 00 0a 06 17 58 0a 06 08 6f ?? 00 00 0a 13 07 12 07 28 ?? 00 00 0a fe 04 13 06 11 06 2d cd } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}