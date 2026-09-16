rule Trojan_BAT_AgentTesla_AT_MTB_9{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 00 6d 00 61 00 67 00 69 00 6e 00 65 00 72 00 2e 00 6d 00 61 00 6c 00 68 00 65 00 75 00 72 00 65 00 75 00 78 00 } 		$a_01_1 = {43 00 61 00 6e 00 53 00 65 00 65 00 6b 00 } 		$a_01_2 = {52 43 32 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}