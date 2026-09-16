rule Trojan_BAT_AgentTesla_FA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {06 07 16 20 00 10 00 00 6f ?? ?? ?? 0a 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f ?? ?? ?? 0a ?? ?? ?? 09 16 fe 02 13 05 11 05 2d d0 08 6f ?? ?? ?? 0a 13 06 de 16 08 2c 07 08 6f ?? ?? ?? 0a 00 dc } 		$a_81_1 = {47 5a 49 44 45 4b 4b 4b 4b } 		$a_81_2 = {47 5a 69 70 53 74 72 65 61 6d } 		$a_81_3 = {41 45 53 5f 44 65 63 72 79 70 74 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}