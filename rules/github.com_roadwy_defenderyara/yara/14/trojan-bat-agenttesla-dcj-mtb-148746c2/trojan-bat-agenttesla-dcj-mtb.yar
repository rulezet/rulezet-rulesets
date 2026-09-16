rule Trojan_BAT_AgentTesla_DCJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 02 08 18 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 0a 84 28 ?? ?? ?? 06 28 ?? ?? ?? 06 26 } 		$a_03_1 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 ?? ?? ?? 06 9c } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}