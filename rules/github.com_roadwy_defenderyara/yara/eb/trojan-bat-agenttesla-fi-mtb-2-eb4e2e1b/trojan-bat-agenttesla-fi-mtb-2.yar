rule Trojan_BAT_AgentTesla_FI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FI!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 17 58 0a 06 20 00 01 00 00 5d 0a 08 11 06 06 94 58 0c 08 20 00 01 00 00 5d 0c 11 06 06 94 13 04 11 06 06 11 06 08 94 9e 11 06 08 11 04 9e 11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5d 94 0d 11 07 07 02 07 91 09 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 13 0a 11 0a 2d a2 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}