rule Trojan_BAT_AgentTesla_FU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {02 50 06 03 06 02 50 8e 69 59 03 8e 69 58 91 9c 06 17 58 0a 06 02 50 8e 69 32 e5 } 		$a_03_1 = {13 04 12 01 07 8e 69 11 04 8e 69 58 28 ?? ?? ?? 06 12 01 11 04 28 ?? ?? ?? 06 08 17 58 0c 08 } 		$a_81_2 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } 		$a_81_3 = {67 65 74 5f 50 69 78 65 6c 46 6f 72 6d 61 74 } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=12
 
}