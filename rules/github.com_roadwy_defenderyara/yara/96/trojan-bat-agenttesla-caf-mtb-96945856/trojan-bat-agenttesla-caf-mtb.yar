rule Trojan_BAT_AgentTesla_CAF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c } 		$a_02_1 = {07 02 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 84 28 ?? ?? ?? 06 28 ?? ?? ?? 06 26 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}