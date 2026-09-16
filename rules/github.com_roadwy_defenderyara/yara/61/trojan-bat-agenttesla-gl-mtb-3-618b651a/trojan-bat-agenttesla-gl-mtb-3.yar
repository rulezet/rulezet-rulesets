rule Trojan_BAT_AgentTesla_GL_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.GL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 73 65 36 34 53 74 72 69 6e 67 00 52 65 70 6c 61 63 65 00 } 		$a_01_1 = {1e 1e 0d 0d 0d 0d 0d 1e 1e 0d 0d 0d 57 64 ab 11 } 		$a_01_2 = {61 6d 20 74 72 6e 6e 6f 74 20 73 76 20 72 75 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=2
 
}