rule Trojan_BAT_AgentTesla_SKF_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.SKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {02 06 07 28 05 00 00 06 0c 04 03 6f 40 00 00 0a 59 0d 03 08 09 28 06 00 00 06 07 17 58 0b 07 02 6f 41 00 00 0a 2f 09 03 6f 40 00 00 0a 04 32 d0 } 		$a_81_1 = {4d 65 6d 6f 72 69 2e 50 72 6f 70 65 72 74 69 65 73 } 		$a_81_2 = {24 33 61 31 36 37 32 65 30 2d 30 35 36 34 2d 34 39 32 38 2d 62 62 66 37 2d 35 37 32 63 63 37 65 61 39 32 34 66 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}