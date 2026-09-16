rule Trojan_BAT_AgentTesla_RPX_MTB_12{
	meta:
		description = "Trojan:BAT/AgentTesla.RPX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 4d 01 00 70 28 04 01 00 0a 0b 07 72 51 01 00 70 28 04 01 00 0a 0b 07 72 51 01 00 70 28 04 01 00 0a 0b 07 72 55 01 00 70 28 04 01 00 0a 0b 07 72 59 01 00 70 28 04 01 00 0a 0b 07 72 5d 01 00 70 28 04 01 00 0a 0b 07 72 5d 01 00 70 28 04 01 00 0a 0b 07 72 61 01 00 70 28 04 01 00 0a 0b 07 72 65 01 00 70 28 04 01 00 0a 0b 07 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}