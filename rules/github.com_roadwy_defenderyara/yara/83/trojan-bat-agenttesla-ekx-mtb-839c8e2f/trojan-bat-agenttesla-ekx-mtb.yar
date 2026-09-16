rule Trojan_BAT_AgentTesla_EKX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 08 09 6f ?? ?? ?? 0a 13 0a 11 0a 16 16 16 16 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 0b 11 0b 2c 27 07 12 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 12 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 12 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 17 d6 0d } 		$a_01_1 = {00 47 65 74 50 69 78 65 6c 00 } 		$a_01_2 = {00 46 72 6f 6d 41 72 67 62 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}