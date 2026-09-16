rule Trojan_BAT_AgentTesla_MBU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {34 44 2d 35 41 2d 39 4f 2d 4f 4f 2d 4f 33 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 4f 34 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 46 46 2d 46 46 2d 4f 4f 2d 4f 4f 2d 42 38 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 4f 4f 2d 34 4f } 		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 } 		$a_01_2 = {53 70 6c 69 74 } 		$a_01_3 = {54 00 6f 00 42 00 79 00 74 00 65 00 } 		$a_01_4 = {52 65 70 6c 61 63 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}