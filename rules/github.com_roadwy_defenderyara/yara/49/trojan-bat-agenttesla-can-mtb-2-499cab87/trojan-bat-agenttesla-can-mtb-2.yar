rule Trojan_BAT_AgentTesla_CAN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 3a 09 17 8d ?? 00 00 01 25 16 08 17 8d ?? 00 00 01 25 16 11 04 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 11 04 17 d6 13 04 00 11 04 } 		$a_01_1 = {53 70 6c 69 74 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}