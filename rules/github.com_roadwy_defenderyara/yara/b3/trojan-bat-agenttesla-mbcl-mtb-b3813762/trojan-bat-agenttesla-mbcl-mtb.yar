rule Trojan_BAT_AgentTesla_MBCL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 11 09 17 7e ?? 00 00 0a a2 11 09 18 11 06 72 de 07 00 70 6f ?? 00 00 0a a2 11 09 13 0a 11 0a 13 0b 1f 1a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}