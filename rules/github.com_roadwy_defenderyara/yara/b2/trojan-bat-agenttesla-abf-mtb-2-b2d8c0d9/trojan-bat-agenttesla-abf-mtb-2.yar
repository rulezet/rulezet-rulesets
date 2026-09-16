rule Trojan_BAT_AgentTesla_ABF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 09 16 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 0b 07 16 fe 02 13 06 11 06 2c 09 06 09 16 07 6f ?? ?? ?? 0a 07 16 fe 02 13 07 11 07 2d d5 06 6f ?? ?? ?? 0a 13 05 de 0a } 		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } 		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } 		$a_01_3 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}