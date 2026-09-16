rule Trojan_BAT_AgentTesla_RB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 17 1e 9e 25 18 1f 09 9e 25 19 1f 11 9e 25 1a 1f 12 9e 25 1b 1f 1a 9e 80 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}