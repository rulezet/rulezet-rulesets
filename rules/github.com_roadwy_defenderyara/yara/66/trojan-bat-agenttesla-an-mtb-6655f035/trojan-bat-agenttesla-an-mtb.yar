rule Trojan_BAT_AgentTesla_AN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 9a 20 08 12 00 00 95 e0 95 7e 2e 00 00 04 16 9a 20 33 03 00 00 95 61 7e 2e 00 00 04 16 9a 20 ef 0d 00 00 95 2e 03 17 2b 01 16 58 } 		$a_01_1 = {95 2e 03 16 2b 01 17 17 59 7e 2e 00 00 04 16 9a 20 12 03 00 00 95 5f 7e 2e 00 00 04 16 9a 20 f8 0f 00 00 95 61 58 80 35 00 00 04 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}