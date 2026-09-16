rule Trojan_BAT_AgentTesla_ARR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 1f 19 62 2b 1e 1d 5f 60 16 2d f6 2b 19 1d 2c ef 1e 2c ec 2b 14 2b 15 16 2c 15 26 26 } 		$a_01_1 = {11 07 a2 09 1a 2c 0d 17 25 2c 0a 25 2c 07 58 1a 2c 9f } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}