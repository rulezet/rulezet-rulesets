rule Trojan_BAT_AgentTesla_AMK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 07 07 11 07 91 28 46 00 00 0a 11 07 17 58 13 07 11 07 07 8e 69 32 e6 } 		$a_01_1 = {4b 75 6b 72 69 42 72 61 69 6e 73 43 61 74 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}