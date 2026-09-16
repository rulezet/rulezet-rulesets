rule Trojan_BAT_AgentTesla_SPQX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPQX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {45 50 30 42 52 44 73 72 6b 74 70 42 52 33 33 36 } 		$a_81_1 = {6d 73 65 6e 63 68 69 6a 4b 43 61 74 74 } 		$a_81_2 = {77 30 30 64 67 54 53 6f 63 6b 65 6e 65 44 70 73 } 		$a_81_3 = {6f 6d 71 74 7a 73 6f 66 74 37 57 32 38 35 2e 64 6c 6c } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}