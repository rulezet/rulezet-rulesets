rule Trojan_BAT_AgentTesla_GB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 77 00 79 00 6d 00 61 00 73 00 63 00 65 00 6e 00 73 00 6f 00 72 00 65 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 } 		$a_01_1 = {59 00 6f 00 74 00 74 00 61 00 62 00 69 00 74 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}