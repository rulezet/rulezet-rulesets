rule Trojan_BAT_AgentTesla_ENR_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ENR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 91 7e ?? ?? ?? 04 11 07 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 61 9c 11 07 17 d6 13 07 } 		$a_01_1 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}