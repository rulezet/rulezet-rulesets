rule Trojan_BAT_AgentTesla_CAF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 1d 12 03 2b 1c 2b 21 07 02 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a de 20 08 2b e0 28 ?? 00 00 0a 2b dd 06 2b dc } 		$a_01_1 = {54 6f 42 79 74 65 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}