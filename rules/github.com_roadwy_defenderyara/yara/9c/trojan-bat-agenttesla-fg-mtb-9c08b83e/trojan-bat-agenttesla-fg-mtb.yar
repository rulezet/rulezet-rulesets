rule Trojan_BAT_AgentTesla_FG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 04 73 84 00 00 0a 0a 73 6c 00 00 0a 0b 73 85 00 00 0a 0c 08 06 08 6f 86 00 00 0a 1e 5b 6f 87 00 00 0a 6f 88 00 00 0a 08 06 08 6f 89 00 00 0a 1e 5b 6f 87 00 00 0a 6f 8a 00 00 0a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}