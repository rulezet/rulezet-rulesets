rule Trojan_BAT_AgentTesla_ESN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ESN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 11 06 02 11 06 91 08 18 d6 18 da 61 07 11 07 19 d6 19 da 91 61 b4 9c 11 07 } 		$a_03_1 = {2b 6e 02 09 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}