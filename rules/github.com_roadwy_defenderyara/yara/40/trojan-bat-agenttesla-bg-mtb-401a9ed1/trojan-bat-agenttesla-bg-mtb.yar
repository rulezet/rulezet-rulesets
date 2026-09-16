rule Trojan_BAT_AgentTesla_BG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 67 72 61 6d 31 74 61 6e 6e 6f 74 20 62 76 31 72 75 6e 20 69 6e 20 55 60 53 20 6d 6f 64 65 } 		$a_01_1 = {6b 65 72 6e 65 6c 33 43 3f 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}