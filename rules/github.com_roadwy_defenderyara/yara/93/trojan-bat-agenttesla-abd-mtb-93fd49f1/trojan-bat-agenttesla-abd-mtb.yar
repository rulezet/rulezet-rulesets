rule Trojan_BAT_AgentTesla_ABD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 b0 0b 00 00 95 2e 03 16 2b 01 17 7e 22 00 00 04 20 e4 0a 00 00 95 5a 7e 22 00 00 04 20 d9 08 00 00 95 58 61 81 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}