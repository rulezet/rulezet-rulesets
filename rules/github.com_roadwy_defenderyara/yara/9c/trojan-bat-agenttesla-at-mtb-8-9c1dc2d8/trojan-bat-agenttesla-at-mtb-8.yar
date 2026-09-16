rule Trojan_BAT_AgentTesla_AT_MTB_8{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 3b 00 00 06 17 2d 1c 26 28 30 00 00 0a 06 6f 31 00 00 0a 28 32 00 00 0a 28 43 00 00 06 18 2d 06 26 de 09 0a 2b e2 0b 2b f8 26 de d2 } 		$a_01_1 = {16 1a 2d 0c 26 02 8e 69 17 59 1a 2d 06 26 2b 24 0a 2b f2 0b 2b f8 02 06 91 16 2c 15 26 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}