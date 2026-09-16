rule Trojan_BAT_AgentTesla_EQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {16 0d 04 17 da 13 04 16 0b 2b 0a 09 03 07 94 d6 0d 07 17 d6 0b 07 11 04 31 f1 09 6c 04 6c 5b 0c 02 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 1f 0a 9a 7d ?? ?? ?? 04 08 0a 2b 00 06 2a } 		$a_81_1 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } 		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}