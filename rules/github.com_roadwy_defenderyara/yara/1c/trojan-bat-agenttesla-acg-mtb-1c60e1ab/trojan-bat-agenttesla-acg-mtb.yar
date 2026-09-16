rule Trojan_BAT_AgentTesla_ACG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ACG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 18 6f ?? 00 00 0a 00 11 05 72 ?? ?? 00 70 12 17 28 ?? 00 00 0a 12 17 28 ?? 00 00 0a 58 12 17 28 ?? 00 00 0a 58 6b 22 00 00 40 40 5b 22 00 00 7f 43 5b 6f } 		$a_03_1 = {02 12 07 28 ?? 00 00 0a 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 13 17 } 	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}