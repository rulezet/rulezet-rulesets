rule Trojan_BAT_AgentTesla_NAC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {6f 17 00 00 0a 25 17 6f ?? 00 00 0a 13 06 73 ?? 00 00 0a 25 11 06 6f ?? 00 00 0a 25 6f ?? 00 00 0a 26 25 } 		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } 		$a_01_2 = {44 65 66 61 75 6c 74 2e 67 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}