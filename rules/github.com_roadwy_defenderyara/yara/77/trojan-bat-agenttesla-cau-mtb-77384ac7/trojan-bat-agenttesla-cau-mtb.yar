rule Trojan_BAT_AgentTesla_CAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 1d 06 09 11 04 09 8e 69 5d 91 08 11 04 91 61 d2 6f ?? 00 00 0a 11 04 17 58 16 2d e1 13 04 11 04 08 8e 69 1c 2c fc } 		$a_01_1 = {47 65 74 42 79 74 65 73 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}