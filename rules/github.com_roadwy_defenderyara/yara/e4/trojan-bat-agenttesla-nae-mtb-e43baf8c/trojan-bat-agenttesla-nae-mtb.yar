rule Trojan_BAT_AgentTesla_NAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 01 28 0d 00 00 06 13 02 38 ?? 00 00 00 28 ?? 00 00 0a 11 00 6f ?? 00 00 0a 28 ?? 00 00 0a 13 01 20 ?? 00 00 00 } 		$a_01_1 = {50 75 61 66 6f 77 72 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}