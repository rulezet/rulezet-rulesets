rule Trojan_BAT_AgentTesla_NFJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1f 1d 93 61 1f 7c 5f 9d 2a } 		$a_03_1 = {1f 64 91 03 5f 20 ?? 00 00 00 5f 9c 59 13 05 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}