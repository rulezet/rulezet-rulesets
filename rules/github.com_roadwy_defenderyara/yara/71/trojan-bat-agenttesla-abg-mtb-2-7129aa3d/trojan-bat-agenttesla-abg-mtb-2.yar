rule Trojan_BAT_AgentTesla_ABG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 09 11 04 6f ?? 00 00 0a 13 06 12 06 28 ?? 00 00 0a 13 07 12 06 28 ?? 00 00 0a 13 08 12 06 28 ?? 00 00 0a 13 09 06 11 07 6f ?? 00 00 06 13 07 06 11 08 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}