rule Trojan_BAT_AgentTesla_NFZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {7e 28 00 00 04 18 9a 20 14 11 00 00 95 5f 7e 28 00 00 04 18 9a 20 9f 08 00 00 95 61 59 81 06 00 00 01 7e 24 00 00 04 7e 2d 00 00 04 36 07 7e 31 00 00 04 } 		$a_01_1 = {20 ef 05 00 00 95 2e 03 17 2b 01 16 58 7e 0d 00 00 04 17 9a 1b 95 7e 0d 00 00 04 16 9a 20 88 0b 00 00 95 61 7e 0d 00 00 04 16 9a 20 03 0c 00 00 95 } 		$a_01_2 = {57 94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}