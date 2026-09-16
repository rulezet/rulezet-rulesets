rule Trojan_BAT_AgentTesla_MBGS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 20 10 27 00 00 13 00 12 00 6f ?? 00 00 06 1c 13 00 12 00 1d 13 01 12 01 } 		$a_01_1 = {4d 6f 64 75 6c 65 31 00 4b 45 53 41 52 } 		$a_01_2 = {41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}