rule Trojan_BAT_AgentTesla_AU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AU!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 68 73 7d 20 70 72 6f 67 72 61 6d 2a 6d 61 6e 6e 6f 74 20 62 65 2a 7c 75 6e 20 69 6e 20 44 4f 5d 2a 6d 6f 64 65 } 		$a_01_1 = {46 41 32 36 30 35 44 42 44 41 34 36 39 30 37 38 41 41 46 41 35 42 37 34 36 41 32 41 30 33 30 36 46 45 37 33 35 42 38 38 33 30 38 33 38 30 38 32 31 46 37 36 41 32 42 41 37 38 33 30 32 30 34 45 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}