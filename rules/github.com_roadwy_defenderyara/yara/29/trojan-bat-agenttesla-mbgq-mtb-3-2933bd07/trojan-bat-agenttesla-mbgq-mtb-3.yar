rule Trojan_BAT_AgentTesla_MBGQ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0a 2b 19 07 06 08 06 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 05 11 05 2d db } 		$a_01_1 = {51 4c 54 56 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}