rule Trojan_BAT_AgentTesla_RD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0b 2b 27 08 06 07 6f 3e 00 00 0a 26 08 06 07 6f 3e 00 00 0a 13 05 11 05 28 3f 00 00 0a 13 06 11 04 09 11 06 d2 9c 07 17 58 0b 07 08 6f 40 00 00 0a fe 04 13 07 11 07 2d ca 09 17 58 0d 06 17 58 0a 06 08 6f 41 00 00 0a fe 04 13 08 11 08 2d af } 		$a_01_1 = {28 43 00 00 0a 02 6f 44 00 00 0a 0a 06 2a } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}