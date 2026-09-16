rule Trojan_BAT_AgentTesla_NED_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6c 6c 6f 72 20 50 61 6c 6c 65 74 65 73 } 		$a_01_1 = {76 34 2e 30 2e 33 30 33 31 39 } 		$a_01_2 = {72 65 6d 6f 76 65 5f 44 6f 57 6f 72 6b } 		$a_01_3 = {62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39 50 41 44 50 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}