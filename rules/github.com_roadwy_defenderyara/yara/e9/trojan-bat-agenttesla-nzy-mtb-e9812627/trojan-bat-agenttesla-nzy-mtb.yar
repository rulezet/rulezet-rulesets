rule Trojan_BAT_AgentTesla_NZY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {54 56 71 51 24 24 24 24 4d 24 24 24 24 24 24 24 24 45 24 24 24 24 24 24 24 24 2f 2f 38 24 24 24 24 4c 67 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 24 51 24 24 24 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}