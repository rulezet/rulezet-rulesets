rule Trojan_BAT_AgentTesla_FT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_00_0 = {02 50 08 02 50 8e 69 6a 5d b7 02 50 08 02 50 8e 69 6a 5d b7 91 03 08 03 8e 69 6a 5d b7 91 61 02 50 08 17 6a d6 02 50 8e 69 6a 5d b7 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 08 17 6a d6 0c 08 07 31 bb } 		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}