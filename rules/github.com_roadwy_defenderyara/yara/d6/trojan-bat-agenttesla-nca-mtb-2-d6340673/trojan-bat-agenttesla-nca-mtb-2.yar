rule Trojan_BAT_AgentTesla_NCA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 02 07 94 d1 0c 12 02 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 07 17 58 0b 07 02 8e 69 32 } 		$a_03_1 = {06 07 02 07 28 ?? ?? ?? 06 07 20 ?? ?? ?? 00 5d d1 61 d1 9d 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 } 		$a_01_2 = {04 03 1f 10 5d 91 61 2a } 		$a_01_3 = {2c 00 2e 00 2d 00 65 00 78 00 2c 00 2e 00 2d 00 65 00 2e 00 73 00 72 00 2c 00 2e 00 2d 00 65 00 73 00 77 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}