rule Trojan_BAT_AgentTesla_BAI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 2d 9d 6f ?? 00 00 0a 0b 07 8e 69 8d ?? 00 00 01 0c 16 0a 2b 12 08 06 07 06 9a 1f 10 28 ?? 00 00 0a d2 9c 06 17 58 0a 06 07 8e 69 fe 04 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}