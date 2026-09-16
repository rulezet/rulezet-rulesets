rule Trojan_BAT_AgentTesla_NZM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 11 04 91 11 01 61 11 00 11 03 91 61 13 09 } 		$a_01_1 = {39 63 38 64 37 63 66 65 65 65 64 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}