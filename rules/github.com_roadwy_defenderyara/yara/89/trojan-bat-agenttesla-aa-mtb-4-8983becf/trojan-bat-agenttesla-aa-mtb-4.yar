rule Trojan_BAT_AgentTesla_AA_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.AA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 79 73 74 75 6d 2e 53 75 63 75 72 79 74 79 2e 53 72 79 70 } 		$a_01_1 = {46 69 6c 75 53 74 72 75 61 6d } 		$a_01_2 = {50 72 6f 74 75 63 74 51 74 74 72 79 62 75 74 75 } 		$a_01_3 = {47 75 6e 65 72 71 74 65 64 53 6f 64 65 51 74 74 72 79 62 75 74 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}