rule Trojan_BAT_AgentTesla_EX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_00_0 = {11 05 11 01 11 08 11 01 11 08 8e 69 5d 91 9e 38 } 		$a_00_1 = {11 07 11 01 03 11 01 91 11 09 61 d2 9c 38 } 		$a_81_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_81_2  & 1)*1) >=21
 
}