rule Trojan_BAT_AgentTesla_NZF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 03 20 00 87 93 03 6f ?? ?? ?? 0a 80 ?? ?? ?? ?? 38 } 		$a_81_1 = {31 38 35 2e 32 34 36 2e 32 32 30 2e 36 35 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}