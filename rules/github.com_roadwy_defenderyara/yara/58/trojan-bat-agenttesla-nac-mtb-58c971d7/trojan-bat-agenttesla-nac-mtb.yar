rule Trojan_BAT_AgentTesla_NAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 07 08 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d dd } 		$a_01_1 = {63 37 39 66 34 63 39 2d 36 37 36 62 2d 34 32 37 63 2d 39 31 35 39 2d 36 63 30 30 33 37 62 34 63 36 } 		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}