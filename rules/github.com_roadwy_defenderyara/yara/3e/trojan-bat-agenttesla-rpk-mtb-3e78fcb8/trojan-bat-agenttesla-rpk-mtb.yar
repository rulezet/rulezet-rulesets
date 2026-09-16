rule Trojan_BAT_AgentTesla_RPK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 59 7e 28 00 00 04 11 07 13 0a 18 9a 20 a0 0d 00 00 11 0d 13 07 95 5f 7e 28 00 00 04 18 9a 20 de 07 00 00 95 61 59 81 06 00 00 01 38 76 07 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}