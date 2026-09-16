rule Trojan_BAT_AgentTesla_NW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 15 00 00 0a 02 72 ?? 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 0a dd 06 00 00 00 } 		$a_01_1 = {45 69 68 6f 72 67 77 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}