rule Trojan_BAT_AgentTesla_RP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5f d2 13 0f 11 06 11 0f 95 d2 13 10 11 13 20 ?? ?? ?? ?? 5a 20 ?? ?? ?? ?? 61 38 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}