rule TrojanSpy_BAT_AgentTesla_2{
	meta:
		description = "TrojanSpy:BAT/AgentTesla,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 67 68 79 74 75 74 67 66 6e 6d 64 66 67 2e 4d 79 } 		$a_01_1 = {50 4f 4f 59 55 47 48 59 46 55 47 2e 4d 79 } 		$a_01_2 = {43 6f 6e 66 75 73 65 72 45 78 20 76 31 2e 30 2e 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}