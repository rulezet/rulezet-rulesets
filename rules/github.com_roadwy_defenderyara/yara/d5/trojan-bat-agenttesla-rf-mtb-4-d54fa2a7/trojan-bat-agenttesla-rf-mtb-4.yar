rule Trojan_BAT_AgentTesla_RF_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {06 07 16 20 [0-04] 6f [0-04] 0d 09 16 fe 02 13 04 11 04 2c 0c ?? 08 07 16 09 6f [0-07] 09 16 fe 02 13 05 11 05 2d d0 } 		$a_81_1 = {47 5a 49 44 45 4b 4b 4b 4b } 		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_3 = {50 72 69 6d 65 72 } 		$a_81_4 = {44 45 53 5f 44 65 63 72 79 70 74 } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}