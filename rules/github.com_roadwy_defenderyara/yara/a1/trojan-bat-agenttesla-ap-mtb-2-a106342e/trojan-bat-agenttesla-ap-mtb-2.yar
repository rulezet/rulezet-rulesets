rule Trojan_BAT_AgentTesla_AP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {19 9a 20 5b 10 00 00 95 e0 95 7e 29 00 00 04 19 9a 20 59 0e 00 00 95 61 7e 29 00 00 04 19 9a 20 1c 03 00 00 95 2e 03 17 2b 01 16 } 		$a_01_1 = {19 9a 20 42 11 00 00 95 5f 7e 29 00 00 04 19 9a 1f 7d 95 61 61 80 27 00 00 04 2b 72 7e 27 00 00 04 7e 29 00 00 04 19 9a 20 5f 06 00 00 95 33 44 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}