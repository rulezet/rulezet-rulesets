rule Trojan_BAT_AgentTesla_NYJ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NYJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {20 cf 8e fb 0e 13 1a 11 1a 20 0d 8f fb 0e fe 02 13 54 11 54 2c 09 20 cf 8e fb 0e 13 1a 2b 1d 11 1a 20 10 8f fb 0e fe 02 16 fe 01 13 55 11 55 2c 08 11 1a 17 58 13 1a 2b 03 16 13 1a 20 dc 8e fb 0e 13 1b 11 1b 20 c0 8e fb 0e fe 02 13 56 11 56 } 		$a_81_1 = {43 6f 6d 70 69 6c 61 74 69 6f 6e 52 65 6c 61 78 61 74 69 6f 6e 73 } 		$a_81_2 = {43 61 74 65 67 6f 72 79 4d 65 6d 62 65 72 73 68 69 70 } 		$a_81_3 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}