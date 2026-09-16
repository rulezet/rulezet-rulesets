rule Trojan_BAT_AgentTesla_AMBH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 00 43 00 32 00 30 00 44 00 43 00 3c 00 3e 00 3c 00 3e 00 3c 00 3e 00 30 00 42 00 32 00 30 00 34 00 43 00 30 00 34 00 3c 00 3e 00 3c 00 3e 00 30 00 37 00 30 00 38 00 31 00 42 00 35 00 41 00 35 00 39 00 33 00 3c 00 3e } 		$a_01_1 = {34 00 44 00 35 00 41 00 39 00 3c 00 3e 00 3c 00 3e 00 33 00 3c 00 3e 00 3c 00 3e 00 3c 00 3e 00 30 00 34 00 3c 00 3e 00 3c 00 3e 00 3c 00 3e 00 46 00 46 00 46 00 46 00 3c 00 3e 00 3c 00 3e 00 42 00 38 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}