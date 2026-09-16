rule Trojan_BAT_AgentTesla_BB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 73 65 72 76 65 72 53 74 61 72 74 65 64 } 		$a_01_1 = {53 65 63 75 72 65 2e 4d 65 73 73 65 6e 67 65 72 2e 57 70 66 48 6f 73 74 } 		$a_01_2 = {55 72 69 4b 69 6e 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}