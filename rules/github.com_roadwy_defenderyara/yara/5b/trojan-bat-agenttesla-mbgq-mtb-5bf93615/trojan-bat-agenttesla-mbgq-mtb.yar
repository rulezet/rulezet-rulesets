rule Trojan_BAT_AgentTesla_MBGQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 00 11 47 00 69 00 61 00 79 00 2e 00 43 00 43 00 4d } 		$a_01_1 = {44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}