rule Trojan_BAT_AgentTesla_A_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 18 5b 8d ?? ?? ?? ?? 0b 16 0c 2b 1a 00 07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d de 07 13 04 2b 00 11 04 2a } 		$a_01_1 = {42 61 69 54 61 70 54 68 69 65 74 4b 65 46 6f 72 6d 2e 66 72 6d 42 61 69 31 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}