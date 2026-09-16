rule Trojan_BAT_AgentTesla_MBGQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 36 62 32 31 39 64 30 30 2d 66 62 38 61 2d 34 66 39 35 2d 39 35 37 38 2d 61 30 32 62 31 38 35 35 62 32 35 65 } 		$a_01_1 = {51 55 41 4e 4c 59 44 41 49 4c 59 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}