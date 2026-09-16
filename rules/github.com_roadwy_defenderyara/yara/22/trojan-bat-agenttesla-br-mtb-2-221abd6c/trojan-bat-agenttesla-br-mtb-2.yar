rule Trojan_BAT_AgentTesla_BR_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {50 65 72 73 6f 6e 61 6c 20 66 69 6e 61 6e 63 65 20 70 6c 61 6e 6e 69 6e 67 20 61 6e 64 20 69 6e 76 65 73 74 6d 65 6e 74 20 61 64 76 69 73 6f 72 79 } 		$a_81_1 = {57 65 61 6c 74 68 57 69 73 65 20 41 64 76 69 73 6f 72 2e 64 6c 6c } 		$a_81_2 = {46 69 6e 54 65 63 68 20 41 64 76 69 73 6f 72 73 20 49 6e 63 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}