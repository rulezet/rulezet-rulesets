rule Trojan_BAT_AgentTesla_SC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 17 58 13 0e 11 06 20 00 56 01 00 5d 13 0b 11 09 11 0b 91 13 0f 11 06 1f 16 5d 13 10 11 09 11 0b 11 0f 1f 16 8d 06 00 00 01 25 d0 15 00 00 04 28 ?? ?? ?? 0a 11 10 91 61 11 09 11 0e 20 00 56 01 00 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 11 06 17 58 13 06 11 06 20 00 56 01 00 fe 04 13 11 11 11 2d 97 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}