rule Trojan_BAT_AgentTesla_AQT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AQT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {02 02 8e 69 17 da 91 1f 70 61 0c 02 8e 69 17 d6 17 da 17 d6 ?? ?? ?? ?? ?? 0d 02 8e 69 17 da 13 04 11 04 13 05 16 13 06 11 06 2c 42 09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c } 		$a_81_1 = {47 65 74 54 79 70 65 } 		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=10
 
}