rule Trojan_BAT_AgentTesla_RPP_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2c 03 17 2b 03 16 2b 00 2d 03 26 2b 07 28 1a 00 00 0a 2b 00 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}