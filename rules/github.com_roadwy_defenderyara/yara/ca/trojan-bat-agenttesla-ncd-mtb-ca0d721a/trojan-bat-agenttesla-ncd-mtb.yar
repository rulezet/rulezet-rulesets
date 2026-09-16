rule Trojan_BAT_AgentTesla_NCD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 06 11 01 00 0c 20 b4 e7 00 00 0d 08 6c 09 6c 23 00 00 00 00 00 00 30 40 5b 58 28 64 00 00 0a b7 13 05 11 05 09 d8 08 d8 13 05 11 04 23 00 00 00 00 00 00 f0 3f 58 13 04 11 04 23 00 00 00 00 00 c2 e6 40 31 ba } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}