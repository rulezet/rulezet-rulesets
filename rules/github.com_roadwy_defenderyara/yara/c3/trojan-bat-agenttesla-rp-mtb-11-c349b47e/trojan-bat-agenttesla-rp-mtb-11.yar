rule Trojan_BAT_AgentTesla_RP_MTB_11{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 72 00 00 06 0a 06 02 7d 42 00 00 04 16 06 7b 42 00 00 04 6f 9d 00 00 0a 18 5b 28 a7 00 00 0a 06 fe 06 73 00 00 06 73 a8 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}