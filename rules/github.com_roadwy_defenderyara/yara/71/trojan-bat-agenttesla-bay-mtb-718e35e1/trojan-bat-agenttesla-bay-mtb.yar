rule Trojan_BAT_AgentTesla_BAY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 ?? 00 00 0a 0c 08 16 08 8e 69 28 ?? 00 00 0a 08 0d de 1b 26 20 88 13 00 00 28 ?? 00 00 0a de 00 } 		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_01_2 = {52 65 76 65 72 73 65 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}