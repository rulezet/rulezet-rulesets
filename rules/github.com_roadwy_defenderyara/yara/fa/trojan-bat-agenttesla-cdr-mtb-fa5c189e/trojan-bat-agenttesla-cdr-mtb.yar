rule Trojan_BAT_AgentTesla_CDR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {08 09 9a 13 04 00 06 11 04 1f 10 28 ?? ?? ?? 0a d1 6f ?? ?? ?? 0a 26 00 09 17 58 0d 09 08 8e 69 } 		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 } 		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } 		$a_81_3 = {47 65 74 54 79 70 65 } 		$a_81_4 = {54 6f 43 68 61 72 41 72 72 61 79 } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}