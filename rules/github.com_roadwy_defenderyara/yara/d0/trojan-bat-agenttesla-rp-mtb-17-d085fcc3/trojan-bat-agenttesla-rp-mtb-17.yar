rule Trojan_BAT_AgentTesla_RP_MTB_17{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 14 00 00 06 73 18 00 00 06 28 12 00 00 06 72 ?? 00 00 70 72 ?? 00 00 70 73 1b 00 00 06 6f 12 00 00 06 72 ?? 00 00 70 72 ?? 00 00 70 73 1f 00 00 06 6f 12 00 00 06 11 02 11 00 6f ?? 00 00 0a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}