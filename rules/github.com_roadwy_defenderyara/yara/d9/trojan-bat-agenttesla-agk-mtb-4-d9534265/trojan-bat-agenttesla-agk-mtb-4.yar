rule Trojan_BAT_AgentTesla_AGK_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.AGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c 11 07 03 6f ?? ?? ?? 0a 17 da fe 01 13 08 11 08 13 09 11 09 2c 06 16 13 07 00 2b 08 00 11 07 17 d6 13 07 00 11 06 17 d6 13 06 11 06 11 05 31 c0 } 		$a_80_1 = {47 65 74 4d 65 74 68 6f 64 } 		$a_80_2 = {47 65 74 54 79 70 65 } 		$a_80_3 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}