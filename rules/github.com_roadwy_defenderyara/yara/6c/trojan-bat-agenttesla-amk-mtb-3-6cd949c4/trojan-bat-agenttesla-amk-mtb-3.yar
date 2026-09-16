rule Trojan_BAT_AgentTesla_AMK_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 69 6e 5c 44 65 62 75 67 5c 53 4c 4e 5c 48 6f 74 65 6c 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 5c 6f 62 6a 5c 44 65 62 75 67 5c 48 6f 74 65 6c 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 2e 70 64 62 } 		$a_01_1 = {48 6f 74 65 6c 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}