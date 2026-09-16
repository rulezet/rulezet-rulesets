rule Trojan_BAT_AgentTesla_RF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 1c 62 11 07 58 13 04 11 05 17 58 13 05 11 05 19 3e ?? ff ff ff 07 08 11 04 1f 10 63 20 ?? 00 00 00 5f 28 ?? 00 00 0a 9c 08 17 58 0c 07 08 11 04 1e 63 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}