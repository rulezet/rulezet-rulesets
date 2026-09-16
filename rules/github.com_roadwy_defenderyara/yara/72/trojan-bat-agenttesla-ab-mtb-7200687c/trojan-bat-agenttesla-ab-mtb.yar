rule Trojan_BAT_AgentTesla_AB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 c7 0b 00 00 95 2e 03 16 2b 04 17 06 13 04 17 59 7e 27 00 00 04 20 a3 11 00 00 95 5f 7e 27 00 00 04 20 d8 01 00 00 95 61 61 80 14 00 00 04 } 		$a_01_1 = {20 b5 09 00 00 95 e0 95 7e 0a 00 00 04 20 b0 0c 00 00 95 61 7e 0a 00 00 04 20 cd 02 00 00 95 2e 03 17 2b 01 16 58 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4) >=4
 
}