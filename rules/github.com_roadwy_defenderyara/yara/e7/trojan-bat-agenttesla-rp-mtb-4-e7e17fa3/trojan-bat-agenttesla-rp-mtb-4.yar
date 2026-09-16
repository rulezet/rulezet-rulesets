rule Trojan_BAT_AgentTesla_RP_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 73 1a 00 00 06 0a 00 06 17 6f 26 00 00 06 00 06 17 6f 23 00 00 0a 00 00 de 0b 06 2c 07 06 6f 24 00 00 0a 00 dc 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}