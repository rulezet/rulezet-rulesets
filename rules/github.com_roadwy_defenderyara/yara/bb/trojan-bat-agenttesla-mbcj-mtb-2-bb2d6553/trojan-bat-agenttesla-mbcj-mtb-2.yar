rule Trojan_BAT_AgentTesla_MBCJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 80 01 00 8d ?? 00 00 01 0b 06 72 73 02 00 70 6f ?? 00 00 0a 74 ?? 00 00 1b 16 07 16 20 00 c0 00 00 28 ?? 00 00 0a 00 06 72 79 02 00 70 6f ?? 00 00 0a 74 ?? 00 00 1b 16 07 20 00 c0 00 00 20 00 c0 00 00 28 ?? 00 00 0a 00 d0 ?? 00 00 01 28 5a 00 00 0a 72 7f 02 00 70 20 00 01 00 00 14 14 17 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}