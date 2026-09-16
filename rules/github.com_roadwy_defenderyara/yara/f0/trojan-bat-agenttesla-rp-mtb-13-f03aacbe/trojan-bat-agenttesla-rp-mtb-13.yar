rule Trojan_BAT_AgentTesla_RP_MTB_13{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 73 c7 00 00 06 25 6f c8 00 00 06 16 6a 6f 25 00 00 0a 25 25 6f c8 00 00 06 6f 2b 00 00 0a 69 6f c9 00 00 06 0a 6f cc 00 00 06 73 2b 00 00 06 28 4c 00 00 06 0b 73 2b 00 00 06 28 4b 00 00 06 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}