rule Trojan_BAT_AgentTesla_SUI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SUI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {0b 16 0c 07 8e 69 0d 11 0a 1f 68 91 20 8e 00 00 00 59 13 09 38 9b fe ff ff 00 08 17 58 13 06 07 08 07 08 91 28 07 00 00 06 08 1f 16 5d 91 61 07 11 06 07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c 1e 13 09 } 		$a_81_1 = {46 44 45 46 43 54 4e 47 48 45 57 41 4f 52 52 38 43 5a 4a 46 } 		$a_81_2 = {54 65 68 63 69 7a 61 74 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}