rule Trojan_BAT_AgentTesla_RPS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 6f 5e 00 00 06 2d 06 73 a0 00 00 0a 7a 20 e8 03 00 00 28 9f 00 00 0a 06 12 02 6f 60 00 00 06 2c de } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}