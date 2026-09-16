rule Trojan_BAT_AgentTesla_DAS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 18 2b 1d 1e 2c f9 2b 1b 2b 20 2b 21 2b 26 2b 2b 2b 30 2b 35 1d 2c ec de 39 28 ?? 00 00 06 2b e1 0a 2b e0 28 ?? 00 00 0a 2b de 06 2b dd 6f ?? 00 00 0a 2b d8 28 ?? 00 00 0a 2b d3 28 ?? 00 00 2b 2b ce 28 ?? 00 00 2b 2b c9 0b 2b c8 } 		$a_01_1 = {52 65 76 65 72 73 65 } 		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}