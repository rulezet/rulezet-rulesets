rule Trojan_BAT_AgentTesla_NBL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 18 7e 9f 00 00 04 1f 72 7e 9f 00 00 04 1f 72 93 7e 9f 00 00 04 20 00 01 00 00 93 61 20 cb 00 00 00 5f 9d 2e 09 } 		$a_03_1 = {04 20 ab 52 e3 48 61 02 61 0a 7e b0 ?? ?? ?? 0c 08 74 44 ?? ?? ?? 25 06 93 0b 06 18 58 93 07 61 0b 18 13 0e 38 7c ff ff ff } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}