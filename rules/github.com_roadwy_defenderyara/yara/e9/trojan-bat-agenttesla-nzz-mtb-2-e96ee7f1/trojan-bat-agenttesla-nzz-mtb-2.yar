rule Trojan_BAT_AgentTesla_NZZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 00 0f 00 28 02 00 00 06 [0-09] d0 01 00 00 1b 28 14 00 00 0a 25 26 28 15 00 00 0a 25 26 a5 01 00 00 1b 0a 2b 00 06 2a } 		$a_03_1 = {11 00 0f 00 28 [0-13] d0 01 00 00 1b 28 ?? 00 00 0a 28 ?? 00 00 0a 25 26 a5 01 00 00 1b 0a 2b 00 06 2a } 		$a_01_2 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*10) >=11
 
}