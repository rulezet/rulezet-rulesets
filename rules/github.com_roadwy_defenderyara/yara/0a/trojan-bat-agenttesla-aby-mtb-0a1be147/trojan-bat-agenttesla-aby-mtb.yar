rule Trojan_BAT_AgentTesla_ABY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {17 9a 20 90 04 00 00 95 6e 31 03 16 2b 01 17 17 59 7e 08 00 00 04 17 9a 20 93 0e 00 00 95 5f 7e 08 00 00 04 17 9a 20 12 0a 00 00 95 61 58 81 06 00 00 01 } 		$a_01_1 = {20 b4 0b 00 00 95 2e 03 16 2b 01 17 17 59 7e 02 00 00 04 20 63 09 00 00 95 5f 7e 02 00 00 04 20 02 0b 00 00 95 61 58 81 07 00 00 01 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}