rule Trojan_BAT_AgentTesla_BLI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BLI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {07 02 09 18 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 06 84 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 09 18 d6 0d 20 05 00 00 00 28 ?? ?? ?? 06 3a ?? ?? ?? ?? 26 09 08 3e } 		$a_00_1 = {02 02 8e 69 17 da 91 1f 70 61 0c 02 8e 69 17 d6 17 da 17 d6 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}