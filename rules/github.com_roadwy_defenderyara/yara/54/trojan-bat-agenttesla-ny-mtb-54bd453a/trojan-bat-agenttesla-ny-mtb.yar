rule Trojan_BAT_AgentTesla_NY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 03 04 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 2b 00 06 2a } 		$a_01_1 = {18 58 19 59 fe 01 13 06 11 06 2c 04 16 0d 2b 04 09 17 58 0d 00 11 04 17 58 13 04 11 04 02 8e 69 17 59 fe 02 16 fe 01 13 07 11 07 2d b8 } 		$a_01_2 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09 03 6f } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}