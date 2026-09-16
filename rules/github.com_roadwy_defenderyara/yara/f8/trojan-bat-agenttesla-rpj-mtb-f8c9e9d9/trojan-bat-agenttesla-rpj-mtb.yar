rule Trojan_BAT_AgentTesla_RPJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 01 00 00 04 18 9a 20 d4 01 00 00 95 80 0a 00 00 04 7e 01 00 00 04 19 ?? ?? 9a 1f 2c 8f 05 00 00 01 25 71 05 00 00 01 ?? ?? 7e 01 00 00 04 18 9a 20 9b 02 00 00 95 61 81 05 00 00 01 2a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}