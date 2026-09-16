rule Trojan_BAT_AgentTesla_SF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 18 5a 18 6f fa 00 00 0a 1f 10 28 fb 00 00 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d dc } 		$a_81_1 = {4e 61 6b 6c 69 79 65 2e 41 6e 61 73 61 79 66 61 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}