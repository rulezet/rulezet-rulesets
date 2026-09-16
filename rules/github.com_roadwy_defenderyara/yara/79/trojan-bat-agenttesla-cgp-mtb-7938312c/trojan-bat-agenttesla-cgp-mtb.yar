rule Trojan_BAT_AgentTesla_CGP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 09 18 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 06 84 28 ?? ?? ?? 06 28 ?? ?? ?? 06 26 09 18 25 } 		$a_01_1 = {09 11 06 11 08 08 61 11 09 61 b4 9c } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}