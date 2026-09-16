rule Trojan_BAT_AgentTesla_DGQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 6f ?? ?? ?? 0a 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a 13 09 12 09 28 ?? ?? ?? 0a fe 04 13 08 11 08 2d ba } 		$a_01_1 = {47 65 74 50 69 78 65 6c } 		$a_01_2 = {54 6f 57 69 6e 33 32 } 		$a_01_3 = {47 65 74 54 79 70 65 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}