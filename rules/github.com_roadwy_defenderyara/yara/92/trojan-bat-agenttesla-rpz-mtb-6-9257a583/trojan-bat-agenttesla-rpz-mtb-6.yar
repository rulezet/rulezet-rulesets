rule Trojan_BAT_AgentTesla_RPZ_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 16 13 04 2b 21 00 07 09 11 04 6f 96 00 00 0a 13 06 08 12 06 28 97 00 00 0a 6f 98 00 00 0a 00 11 04 17 58 13 04 00 11 04 07 6f 99 00 00 0a 13 08 12 08 28 9a 00 00 0a fe 04 13 07 11 07 2d c6 09 17 58 0d 00 09 07 6f 99 00 00 0a 13 08 12 08 28 9b 00 00 0a fe 04 13 09 11 09 2d a3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}