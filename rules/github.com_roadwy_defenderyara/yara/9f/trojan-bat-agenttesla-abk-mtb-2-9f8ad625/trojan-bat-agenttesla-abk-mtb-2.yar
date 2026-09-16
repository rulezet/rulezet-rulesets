rule Trojan_BAT_AgentTesla_ABK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 03 11 07 11 0a 11 0d 94 91 6f 41 00 00 0a 00 11 0b 11 0d 58 13 0b 00 11 0d 17 58 13 0d 11 0d 11 0c fe 04 13 0e 11 0e 2d d6 } 		$a_81_1 = {53 79 73 74 65 6d 5f 43 6f 72 65 49 6e 66 6f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}