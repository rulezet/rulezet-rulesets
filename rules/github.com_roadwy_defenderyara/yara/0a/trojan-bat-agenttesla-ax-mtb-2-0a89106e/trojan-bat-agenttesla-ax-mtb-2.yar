rule Trojan_BAT_AgentTesla_AX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 86 05 00 00 95 80 1f 00 00 04 7e 28 00 00 04 1b 9a 1f 0b 8f 06 00 00 01 25 71 06 00 00 01 7e 28 00 00 04 18 9a 20 7e 07 00 00 95 61 81 06 00 00 01 7e 28 00 00 04 1b 9a 1f 0b 95 7e 28 00 00 04 18 9a 20 ec 02 00 00 95 40 9a 04 00 00 } 		$a_01_1 = {94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}