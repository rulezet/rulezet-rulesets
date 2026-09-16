rule Trojan_BAT_AgentTesla_HB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {91 11 05 11 05 07 84 95 11 05 08 84 95 d7 6e 20 ?? ?? ?? ?? 6a 5f b7 95 61 86 9c 06 11 09 12 00 28 ?? ?? ?? ?? 2d 94 } 		$a_80_1 = {50 72 6f 70 65 72 5f 52 43 34 } 		$a_80_2 = {45 78 65 63 42 79 74 65 73 } 	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}