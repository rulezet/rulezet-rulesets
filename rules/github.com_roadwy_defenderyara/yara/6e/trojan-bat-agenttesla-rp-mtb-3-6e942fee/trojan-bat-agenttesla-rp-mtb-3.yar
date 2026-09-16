rule Trojan_BAT_AgentTesla_RP_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 1f 09 8d 44 00 00 01 25 d0 dc 00 00 04 28 c6 00 00 0a 0a 1f 0a 8d 44 00 00 01 25 d0 dd 00 00 04 28 c6 00 00 0a 0b } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}