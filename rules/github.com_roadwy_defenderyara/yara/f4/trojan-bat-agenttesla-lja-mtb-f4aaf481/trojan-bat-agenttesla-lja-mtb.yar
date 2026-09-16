rule Trojan_BAT_AgentTesla_LJA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 2a 00 08 09 11 04 6f ?? ?? ?? 0a 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 07 06 02 11 06 28 ?? ?? ?? 06 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 07 11 07 2d cb } 		$a_81_1 = {54 6f 57 69 6e 33 32 } 		$a_01_2 = {47 65 74 50 69 78 65 6c } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}