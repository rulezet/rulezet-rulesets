rule Trojan_BAT_AgentTesla_ER_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_00_0 = {16 0a 16 0b 03 0c 16 0d 2b 0c 08 09 94 0b 06 07 d6 0a 09 17 d6 0d 09 08 8e 69 32 ee 02 } 		$a_02_1 = {25 16 02 28 ?? ?? ?? 06 13 04 12 04 28 ?? ?? ?? 06 a2 90 09 06 00 17 8d ?? ?? ?? 01 } 		$a_81_2 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } 		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } 	condition:
		((#a_00_0  & 1)*5+(#a_02_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=13
 
}