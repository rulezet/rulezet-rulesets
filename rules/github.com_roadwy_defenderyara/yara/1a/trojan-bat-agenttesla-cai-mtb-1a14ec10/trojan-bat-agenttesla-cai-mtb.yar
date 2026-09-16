rule Trojan_BAT_AgentTesla_CAI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 06 2b 1b 09 11 06 08 11 06 9a 1f 10 28 ?? 00 00 0a d2 6f ?? 00 00 0a 00 11 06 17 58 13 06 11 06 08 8e 69 fe 04 13 07 11 07 2d d8 } 		$a_01_1 = {53 70 6c 69 74 } 		$a_01_2 = {54 6f 53 42 79 74 65 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}