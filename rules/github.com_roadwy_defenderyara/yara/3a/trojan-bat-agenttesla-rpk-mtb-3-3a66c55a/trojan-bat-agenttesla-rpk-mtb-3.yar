rule Trojan_BAT_AgentTesla_RPK_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 0a 11 06 11 0a 9a 1f 10 28 4f 01 00 0a d2 9c 11 0a 17 58 13 0a 11 0a 11 06 8e 69 fe 04 13 0b 11 0b 2d da } 		$a_01_1 = {4d 00 65 00 6c 00 76 00 69 00 6e 00 2e 00 57 00 68 00 69 00 74 00 65 00 } 		$a_01_2 = {41 00 6d 00 69 00 72 00 43 00 61 00 6c 00 65 00 6e 00 64 00 61 00 72 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}