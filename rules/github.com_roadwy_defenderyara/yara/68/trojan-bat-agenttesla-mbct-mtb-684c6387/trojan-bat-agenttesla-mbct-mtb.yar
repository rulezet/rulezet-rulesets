rule Trojan_BAT_AgentTesla_MBCT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 00 08 09 28 ?? 00 00 0a 02 28 ?? 00 00 06 6f [0-10] 6f 46 00 00 0a 00 08 18 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 13 04 07 13 05 11 04 11 05 16 11 05 8e 69 6f 49 00 00 0a 0a de 11 } 		$a_01_1 = {43 6c 73 45 6e 63 72 79 70 74 44 65 63 72 79 70 74 46 69 6c 65 73 } 		$a_01_2 = {37 61 62 33 36 64 37 62 32 36 31 33 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}