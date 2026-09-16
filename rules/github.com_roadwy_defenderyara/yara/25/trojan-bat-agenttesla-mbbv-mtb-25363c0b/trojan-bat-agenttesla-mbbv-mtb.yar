rule Trojan_BAT_AgentTesla_MBBV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 2b 00 35 00 41 00 2b 00 39 00 7d 00 5c 00 2b 00 7d 00 33 00 5c 00 5c 00 5c 00 2b 00 7d 00 34 00 5c 00 5c 00 5c 00 2b 00 46 00 46 00 2b 00 46 00 46 00 5c 00 5c 00 2b 00 42 00 38 00 5c } 		$a_01_1 = {36 00 39 00 2b 00 37 00 33 00 2b 00 32 00 7d 00 2b 00 37 00 7d 00 2b 00 37 00 32 00 2b 00 36 00 46 00 2b 00 36 00 37 00 2b 00 37 00 32 00 2b 00 36 00 31 00 2b 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}