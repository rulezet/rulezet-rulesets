rule Trojan_BAT_AgentTesla_AGK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 07 5a 61 0a 07 1f 10 28 1a 00 00 06 58 0b 07 1f 14 28 1a 00 00 06 32 e6 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}