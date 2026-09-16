rule Trojan_BAT_AgentTesla_FB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {70 0b 16 0c 02 6f ?? ?? ?? 0a 0d 2b 35 02 08 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 11 04 28 ?? ?? ?? 0a 20 18 04 00 00 da 13 05 07 11 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 08 17 d6 0c 00 08 09 fe 04 13 06 11 06 2d c1 07 0a 2b 00 } 		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}