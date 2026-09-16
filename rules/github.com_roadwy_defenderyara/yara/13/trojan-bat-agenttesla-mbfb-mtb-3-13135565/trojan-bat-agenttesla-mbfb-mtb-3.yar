rule Trojan_BAT_AgentTesla_MBFB_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 11 [0-07] 91 59 20 00 01 00 00 58 20 00 01 00 00 5d } 		$a_81_1 = {47 65 74 54 79 70 65 } 		$a_81_2 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}