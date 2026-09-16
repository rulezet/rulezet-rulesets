rule Trojan_BAT_AgentTesla_RDAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 44 4e 56 69 65 77 65 72 } 		$a_01_1 = {4a 6f 68 6e 20 43 6f 6c 65 6d 61 6e } 		$a_01_2 = {42 45 54 41 20 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}