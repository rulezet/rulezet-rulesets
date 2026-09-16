rule Trojan_BAT_AgentTesla_CDC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {20 16 74 00 00 0c 2b 13 00 72 ?? ?? ?? 70 07 08 28 ?? ?? ?? 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2 } 		$a_01_1 = {42 00 61 00 74 00 63 00 68 00 52 00 75 00 6e 00 6e 00 65 00 72 00 } 		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}