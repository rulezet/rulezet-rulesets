rule Trojan_BAT_AgentTesla_AQG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AQG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {25 16 09 a2 25 17 ?? ?? ?? ?? ?? a2 25 13 04 14 14 18 ?? ?? ?? ?? ?? 25 16 17 9c 25 13 05 17 ?? ?? ?? ?? ?? 26 } 		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_80_2 = {47 65 74 54 79 70 65 } 		$a_80_3 = {53 69 6d 70 6c 65 55 49 2e 4d 44 49 } 	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}