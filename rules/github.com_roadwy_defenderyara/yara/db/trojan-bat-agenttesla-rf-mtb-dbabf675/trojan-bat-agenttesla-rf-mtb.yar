rule Trojan_BAT_AgentTesla_RF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 01 13 24 11 24 2c 06 18 13 0a 00 2b 06 00 1f 52 13 0a 00 1f 26 13 0b 11 0b 1f 31 fe 01 13 25 11 25 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}