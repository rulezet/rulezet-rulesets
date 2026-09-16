rule Trojan_BAT_AgentTesla_T_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.T!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 41 41 51 71 56 54 } 		$a_01_1 = {3d 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}