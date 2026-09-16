rule Trojan_BAT_AgentTesla_NAG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 0f 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 13 01 } 		$a_01_1 = {68 6a 6b 6a 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}