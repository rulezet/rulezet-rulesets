rule Trojan_BAT_AgentTesla_MBGP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 1f 2c 9d 6f ?? 01 00 0a 16 9a 73 ?? 01 00 0a 2a } 		$a_01_1 = {65 65 2d 37 33 66 62 36 36 37 38 63 64 62 65 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}