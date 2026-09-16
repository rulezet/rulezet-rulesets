rule Trojan_BAT_AgentTesla_DRQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DRQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 22 00 08 09 11 04 28 ?? ?? ?? 06 13 07 11 07 28 ?? ?? ?? 0a 13 08 07 06 11 08 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 09 11 09 2d d3 06 17 58 0a 00 09 17 58 0d } 		$a_01_1 = {00 47 65 74 50 69 78 65 6c 00 } 		$a_01_2 = {00 54 6f 57 69 6e 33 32 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}