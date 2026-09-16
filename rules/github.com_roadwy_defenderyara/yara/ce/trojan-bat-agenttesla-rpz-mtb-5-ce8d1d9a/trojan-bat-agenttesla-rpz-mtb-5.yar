rule Trojan_BAT_AgentTesla_RPZ_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {7e 1e 00 00 04 0a 06 28 31 00 00 0a 7e 1e 00 00 04 02 12 02 6f 32 00 00 0a 2c 04 08 0b de 11 02 17 28 21 00 00 06 0b de 07 06 28 33 00 00 0a dc 07 2a } 		$a_01_1 = {44 69 63 74 69 6f 6e 61 72 79 } 		$a_01_2 = {43 6f 6e 63 61 74 } 		$a_01_3 = {54 72 79 47 65 74 56 61 6c 75 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}