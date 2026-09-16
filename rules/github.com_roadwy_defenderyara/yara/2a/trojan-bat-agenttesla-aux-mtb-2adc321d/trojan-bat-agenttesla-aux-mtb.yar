rule Trojan_BAT_AgentTesla_AUX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AUX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {09 17 d6 0d 17 0a ?? ?? ?? ?? ?? 07 17 d6 0b 1d 0a 2b ?? 02 11 ?? ?? ?? ?? ?? ?? 26 1e 0a 2b ?? 11 ?? ?? ?? ?? ?? ?? 13 ?? 1c 0a 2b ?? 08 17 d6 0c 1b 0a 2b ?? 08 16 fe 02 16 fe 01 13 ?? 11 ?? 2c } 		$a_80_1 = {47 65 74 50 69 78 65 6c } 		$a_80_2 = {54 6f 57 69 6e 33 32 } 	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}