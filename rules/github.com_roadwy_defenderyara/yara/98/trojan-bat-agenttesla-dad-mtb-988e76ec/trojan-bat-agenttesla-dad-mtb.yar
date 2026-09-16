rule Trojan_BAT_AgentTesla_DAD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 04 16 13 07 2b 18 00 11 04 11 07 09 11 07 9a 1f 10 28 ?? 00 00 0a 9c 00 11 07 17 58 13 07 11 07 09 8e 69 fe 04 13 08 11 08 2d db } 		$a_01_1 = {53 70 6c 69 74 } 		$a_01_2 = {54 6f 42 79 74 65 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}