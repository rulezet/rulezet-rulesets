rule Trojan_BAT_AgentTesla_NC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 03 17 58 ?? ?? ?? ?? ?? 5d 91 0a 16 0b 02 03 28 } 		$a_03_1 = {02 03 1f 16 28 ?? ?? ?? 06 0a 06 0b 2b 00 07 2a } 		$a_01_2 = {20 16 f8 00 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}