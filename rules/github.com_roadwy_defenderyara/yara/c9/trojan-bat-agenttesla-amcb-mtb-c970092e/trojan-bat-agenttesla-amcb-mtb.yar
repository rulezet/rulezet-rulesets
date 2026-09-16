rule Trojan_BAT_AgentTesla_AMCB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 72 01 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 06 28 ?? 00 00 0a 72 01 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0b de 0a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}