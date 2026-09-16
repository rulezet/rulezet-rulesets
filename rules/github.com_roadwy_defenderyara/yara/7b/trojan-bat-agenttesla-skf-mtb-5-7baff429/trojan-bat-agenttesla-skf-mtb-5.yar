rule Trojan_BAT_AgentTesla_SKF_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.SKF!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 02 06 07 28 f0 00 00 06 0c 04 03 6f f6 00 00 0a 59 0d 03 08 09 28 f2 00 00 06 00 03 08 09 28 f4 00 00 06 00 03 04 28 f5 00 00 06 00 00 07 17 58 0b 07 02 6f f7 00 00 0a fe 04 13 04 11 04 2d bf } 		$a_01_1 = {43 6f 6e 42 6f 6f 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 		$a_01_2 = {43 6f 6e 42 6f 6f 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}