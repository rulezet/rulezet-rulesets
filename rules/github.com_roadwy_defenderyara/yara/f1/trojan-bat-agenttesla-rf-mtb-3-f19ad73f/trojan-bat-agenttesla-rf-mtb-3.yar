rule Trojan_BAT_AgentTesla_RF_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 00 68 00 72 00 69 00 73 00 74 00 69 00 61 00 6e 00 62 00 65 00 6c 00 74 00 72 00 61 00 6e 00 2e 00 63 00 6f 00 2f 00 77 00 70 00 2d 00 61 00 64 00 6d 00 69 00 6e 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 63 00 73 00 73 00 2f 00 67 00 72 00 6f 00 75 00 6e 00 64 00 2f 00 62 00 6f 00 } 		$a_01_1 = {53 6c 65 65 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}