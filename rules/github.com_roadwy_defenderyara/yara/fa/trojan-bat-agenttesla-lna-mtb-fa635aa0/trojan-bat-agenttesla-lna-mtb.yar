rule Trojan_BAT_AgentTesla_LNA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 05 2b 31 00 09 11 04 11 05 6f ?? ?? ?? 0a 13 06 09 11 04 11 05 6f ?? ?? ?? 0a 13 07 17 13 08 00 08 07 02 11 07 28 ?? ?? ?? 06 d2 9c 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 09 11 09 2d c4 } 		$a_01_1 = {54 6f 57 69 6e 33 32 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}