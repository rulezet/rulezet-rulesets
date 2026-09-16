rule Trojan_BAT_AgentTesla_EKX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 07 9a 0c 00 00 08 6f ?? ?? ?? 0a 0d 16 13 04 2b 2f 09 11 04 9a 13 05 00 11 05 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 13 06 11 06 2c 0a 00 11 05 28 ?? ?? ?? 06 00 00 00 11 04 17 58 13 04 11 04 09 8e 69 } 		$a_01_1 = {00 47 65 74 4d 65 74 68 6f 64 00 } 		$a_01_2 = {00 47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}