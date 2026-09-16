rule Trojan_BAT_AgentTesla_FF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 50 8e 69 6a 5d b7 03 50 ?? 03 50 8e 69 6a 5d b7 91 ?? ?? ?? 8e 69 6a 5d b7 91 61 03 50 ?? 17 6a d6 03 50 8e 69 6a 5d b7 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 } 		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}