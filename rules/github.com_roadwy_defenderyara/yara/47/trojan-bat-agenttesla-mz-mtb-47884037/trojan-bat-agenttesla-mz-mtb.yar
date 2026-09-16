rule Trojan_BAT_AgentTesla_MZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {1c 9a 0b 07 19 8d ?? ?? 00 01 25 16 7e ?? ?? 00 04 a2 25 17 7e ?? ?? 00 04 a2 25 18 72 ?? ?? 00 70 a2 28 ?? ?? 00 0a 26 } 		$a_80_1 = {41 74 68 6c 65 74 69 63 43 6c 75 62 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}