rule Trojan_BAT_AgentTesla_NAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 02 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 0a dd ?? 00 00 00 } 		$a_01_1 = {43 34 50 52 4f 4c 61 75 6e 63 68 65 72 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}