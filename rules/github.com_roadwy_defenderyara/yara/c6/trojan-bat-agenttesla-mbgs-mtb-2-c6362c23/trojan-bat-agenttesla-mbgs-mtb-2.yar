rule Trojan_BAT_AgentTesla_MBGS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 31 11 08 06 08 58 17 58 17 59 07 09 58 17 58 17 59 6f ?? 00 00 0a 13 11 12 11 28 ?? 00 00 0a 13 0b 11 05 11 04 11 0b 9c 11 04 17 58 13 04 09 17 58 0d 09 17 fe 04 13 0c 11 0c 2d c5 } 		$a_01_1 = {16 13 04 20 01 84 00 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}