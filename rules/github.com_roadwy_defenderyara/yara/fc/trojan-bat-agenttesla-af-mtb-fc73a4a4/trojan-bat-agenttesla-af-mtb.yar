rule Trojan_BAT_AgentTesla_AF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {95 2e 03 17 2b 01 16 58 7e 2a 00 00 04 7e 10 00 00 04 20 0d 07 00 00 95 e0 95 7e 10 00 00 04 20 de 0f 00 00 95 61 7e 10 00 00 04 20 fa 0c 00 00 95 2e 03 17 2b 01 16 } 		$a_01_1 = {20 c5 0d 00 00 95 e0 95 7e 10 00 00 04 20 8e 11 00 00 95 61 7e 10 00 00 04 20 b4 0e 00 00 95 2e 03 17 2b 01 16 58 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}