rule Trojan_BAT_AgentTesla_MBCK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 c1 16 00 70 0b 16 13 05 2b 2b 00 07 06 72 f3 16 00 70 12 05 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 74 ?? 00 00 01 28 ?? 00 00 0a 0b 00 11 05 17 58 13 05 11 05 1f 34 fe 02 16 fe 01 13 06 11 06 2d c6 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}