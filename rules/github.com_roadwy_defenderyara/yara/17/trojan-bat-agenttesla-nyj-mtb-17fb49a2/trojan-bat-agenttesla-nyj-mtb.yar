rule Trojan_BAT_AgentTesla_NYJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 06 5d 0d 03 11 04 9a 0b 03 11 04 03 09 9a a2 03 09 07 a2 00 11 04 17 58 13 04 11 04 06 fe 02 16 fe 01 13 05 11 05 2d d1 } 		$a_01_1 = {1f a2 0b 09 03 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 a8 00 00 00 33 00 00 00 4c 01 00 00 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}