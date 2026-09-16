rule Trojan_BAT_AgentTesla_ES_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {0a 18 5b 0a 73 ?? ?? ?? 0a 0b 16 0c 2b 1e 00 07 02 08 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 08 17 58 0c 08 06 fe 04 0d 09 2d da 07 6f ?? ?? ?? 0a 13 04 2b 00 11 04 2a } 		$a_81_1 = {52 65 70 6c 61 63 65 } 		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } 		$a_81_3 = {43 6c 69 63 6b } 		$a_81_4 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}