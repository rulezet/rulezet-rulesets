rule Trojan_BAT_AgentTesla_AT_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {1a 9a 20 e6 06 00 00 95 e0 95 7e 0e 00 00 04 1a 9a 20 ab 0b 00 00 95 61 7e 0e 00 00 04 1a 9a 20 e2 0c 00 00 95 } 		$a_01_1 = {1a 9a 20 94 10 00 00 95 e0 95 7e 0e 00 00 04 1a 9a 20 05 10 00 00 95 61 7e 0e 00 00 04 1a 9a 20 f9 07 00 00 95 2e 03 17 2b 01 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}