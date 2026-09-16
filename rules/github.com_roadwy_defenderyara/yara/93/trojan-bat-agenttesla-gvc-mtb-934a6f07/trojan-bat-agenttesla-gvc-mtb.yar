rule Trojan_BAT_AgentTesla_GVC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 19 8d 49 00 00 01 25 16 72 01 00 00 70 a2 25 17 72 13 00 00 70 a2 25 18 72 21 00 00 70 a2 0b } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}