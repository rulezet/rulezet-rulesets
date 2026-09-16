rule Trojan_BAT_AgentTesla_BD_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.BD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 65 33 35 66 39 33 38 39 2d 35 63 66 32 2d 34 65 61 37 2d 39 38 34 30 2d 66 36 66 66 35 34 36 30 37 37 64 61 } 		$a_01_1 = {42 6c 69 74 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}