rule Trojan_BAT_AgentTesla_RPX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 05 11 1f 9a 1f 10 28 03 01 00 0a 86 6f 04 01 00 0a 00 11 1f 17 d6 13 1f 11 1f 11 1e 31 df } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}