rule Trojan_BAT_AgentTesla_NRE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {11 07 17 58 13 07 11 07 11 06 8e 69 fe 04 13 08 11 } 		$a_01_1 = {58 69 64 65 72 } 		$a_01_2 = {55 6c 74 72 61 76 69 6f 6c 65 74 } 		$a_01_3 = {52 65 63 6f 6c 61 72 } 		$a_01_4 = {43 00 79 00 62 00 65 00 72 00 58 00 69 00 64 00 65 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}