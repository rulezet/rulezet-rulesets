rule Trojan_BAT_AgentTesla_EAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 07 95 28 ?? ?? ?? 0a 0c 16 0d 2b 0e 06 07 1a 5a 09 58 08 09 91 9c 09 17 58 0d 09 08 8e 69 fe 04 13 04 11 04 2d e6 00 07 17 58 0b } 		$a_01_1 = {00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00 } 		$a_01_2 = {00 43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}