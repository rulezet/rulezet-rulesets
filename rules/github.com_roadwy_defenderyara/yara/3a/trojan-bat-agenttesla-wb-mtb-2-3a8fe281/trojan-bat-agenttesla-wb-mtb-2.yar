rule Trojan_BAT_AgentTesla_WB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.WB!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {02 03 91 19 59 1b 59 d2 2a } 		$a_01_1 = {02 03 02 03 28 0a 00 00 06 25 0a 9c 06 2a } 		$a_01_2 = {8d 2d 00 00 01 25 d0 21 00 00 04 16 2c 03 26 26 2a 28 16 00 00 0a 2b f8 32 02 28 37 00 00 } 		$a_01_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}