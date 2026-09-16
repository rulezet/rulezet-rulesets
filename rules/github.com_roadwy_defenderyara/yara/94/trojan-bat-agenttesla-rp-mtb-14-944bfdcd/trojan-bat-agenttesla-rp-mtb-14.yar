rule Trojan_BAT_AgentTesla_RP_MTB_14{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 4d 61 72 63 61 } 		$a_01_1 = {73 65 74 5f 50 72 65 63 69 6f } 		$a_01_2 = {67 65 74 5f 43 6f 64 69 67 6f } 		$a_01_3 = {67 65 74 5f 4e 6f 6d 62 72 65 } 		$a_01_4 = {02 07 11 05 91 11 06 61 11 08 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}