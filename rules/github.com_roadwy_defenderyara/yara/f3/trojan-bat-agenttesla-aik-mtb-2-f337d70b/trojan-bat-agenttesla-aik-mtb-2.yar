rule Trojan_BAT_AgentTesla_AIK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 45 02 00 04 07 9a 06 28 a0 00 00 0a 39 0b 00 00 00 7e 46 02 00 04 74 25 00 00 01 2a 07 17 58 0b 07 7e 45 02 00 04 8e 69 3f d2 ff ff ff } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}