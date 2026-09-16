rule Trojan_BAT_AgentTesla_RPJ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 23 00 00 00 00 00 88 d3 40 73 1f 00 00 0a 0a 06 02 fe 06 06 00 00 06 73 20 00 00 0a 6f 21 00 00 0a 00 06 17 6f 22 00 00 0a 00 06 16 6f 23 00 00 0a 00 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}