rule Trojan_BAT_AgentTesla_FO_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_00_0 = {02 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 16 0d 2b 18 02 08 02 08 91 06 09 91 07 1f 1f 5f 62 09 61 08 58 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e2 08 17 58 0c 08 02 8e 69 32 c5 } 		$a_81_1 = {44 65 63 6f 6d 70 72 65 73 73 } 		$a_81_2 = {44 65 63 72 79 70 74 } 		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}