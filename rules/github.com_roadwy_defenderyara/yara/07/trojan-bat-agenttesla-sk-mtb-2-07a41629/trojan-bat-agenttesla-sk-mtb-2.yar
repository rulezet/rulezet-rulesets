rule Trojan_BAT_AgentTesla_SK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 10 18 d8 13 11 08 11 11 6f 18 01 00 0a 28 5d 03 00 06 13 12 08 11 11 17 d6 6f 18 01 00 0a 28 5d 03 00 06 13 13 11 06 11 10 11 12 1a 62 11 13 60 b4 9c 11 10 20 ff 03 00 00 5f 2d 0a 28 52 02 00 0a 16 fe 04 2b 01 16 13 14 11 14 2c 08 17 28 06 01 00 0a 00 00 00 11 10 17 d6 13 10 11 10 11 0f 31 9d } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}