rule Trojan_BAT_AgentTesla_CAH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {09 11 04 6f ?? ?? ?? 0a 13 05 07 11 05 28 ?? ?? ?? 0a 08 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 00 11 04 17 d6 13 04 11 04 09 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d c5 } 		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 } 		$a_81_2 = {47 65 74 54 79 70 65 } 		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}