rule Trojan_BAT_AgentTesla_MBCI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 bb 03 00 70 6f ?? 00 00 0a 74 ?? 00 00 1b 0c 08 28 ?? 00 00 0a 07 08 6f ?? 00 00 0a 07 06 72 c7 03 00 70 6f ?? 00 00 0a 74 ?? 00 00 1b 6f ?? 00 00 0a 07 06 72 d3 03 00 70 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}