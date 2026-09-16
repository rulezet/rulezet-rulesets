rule Trojan_BAT_AgentTesla_ABS_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {95 e0 11 0b 13 0b 95 2d 03 16 2b 01 17 17 59 7e 1d 00 00 04 19 9a 20 f4 03 00 00 95 5f 7e 1d 00 00 04 19 06 0a 9a 20 73 02 00 00 95 61 58 81 05 00 00 01 } 		$a_01_1 = {58 7e 0e 00 00 04 35 03 16 2b 01 17 17 59 7e 19 00 00 04 19 9a 20 13 05 00 00 95 5f 7e 19 00 00 04 19 9a 20 16 05 00 00 95 61 58 81 06 00 00 01 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}