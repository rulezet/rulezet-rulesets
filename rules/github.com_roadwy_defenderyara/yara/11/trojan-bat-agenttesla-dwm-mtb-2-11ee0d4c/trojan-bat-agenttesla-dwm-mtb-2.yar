rule Trojan_BAT_AgentTesla_DWM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 08 18 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 06 84 28 ?? ?? ?? 06 28 ?? ?? ?? 06 26 } 		$a_03_1 = {08 11 04 7e ?? ?? ?? 04 02 11 04 91 07 61 06 09 91 61 28 ?? ?? ?? 06 9c 09 16 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}