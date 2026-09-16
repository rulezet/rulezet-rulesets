rule Trojan_BAT_AgentTesla_DMD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 2f 00 08 09 11 04 6f ?? ?? ?? 0a 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 17 13 07 00 07 06 02 11 06 28 ?? ?? ?? 06 d2 9c 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 08 11 08 2d c6 } 		$a_01_1 = {00 47 65 74 50 69 78 65 6c 00 } 		$a_01_2 = {00 47 65 74 54 79 70 65 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}