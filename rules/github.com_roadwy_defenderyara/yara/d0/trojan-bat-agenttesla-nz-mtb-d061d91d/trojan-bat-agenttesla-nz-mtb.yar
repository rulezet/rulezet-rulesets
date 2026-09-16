rule Trojan_BAT_AgentTesla_NZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 18 13 06 2b 96 06 1f 11 d8 0b 1f 10 8d ?? ?? ?? 01 0c 17 0d 1a } 		$a_01_1 = {34 39 63 37 61 33 62 66 39 37 33 37 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}