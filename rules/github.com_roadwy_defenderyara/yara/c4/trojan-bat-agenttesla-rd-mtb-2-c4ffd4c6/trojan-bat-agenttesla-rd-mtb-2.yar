rule Trojan_BAT_AgentTesla_RD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 0c 11 0d 9a 13 08 00 02 11 07 11 08 28 02 00 00 06 00 00 11 0d 17 58 13 0d 11 0d 11 0c 8e 69 fe 04 13 0e 11 0e 2d d8 } 		$a_01_1 = {54 00 79 00 78 00 69 00 66 00 2e 00 65 00 78 00 65 00 } 		$a_01_2 = {53 68 61 72 70 44 65 76 65 6c 6f 70 20 50 72 6f 6a 65 63 74 73 5c 54 79 78 69 66 5c 54 79 78 69 66 5c 6f 62 6a 5c 44 65 62 75 67 5c 54 79 78 69 66 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}