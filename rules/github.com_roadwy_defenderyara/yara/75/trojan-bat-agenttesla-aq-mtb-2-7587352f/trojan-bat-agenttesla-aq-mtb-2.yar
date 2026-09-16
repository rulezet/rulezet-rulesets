rule Trojan_BAT_AgentTesla_AQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {1b 9a 20 9f 0f 00 00 95 e0 95 7e 2a 00 00 04 1b 9a 20 64 03 00 00 95 61 7e 2a 00 00 04 1b 9a 20 f8 09 00 00 95 2e 03 17 2b 01 16 58 } 		$a_01_1 = {1b 9a 20 af 0f 00 00 95 5f 7e 2a 00 00 04 1b 9a 20 86 08 00 00 95 61 61 81 05 00 00 01 7e 2a 00 00 04 19 9a 1f 2f 95 7e 2a 00 00 04 1b 9a 20 39 05 00 00 95 33 6c } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}