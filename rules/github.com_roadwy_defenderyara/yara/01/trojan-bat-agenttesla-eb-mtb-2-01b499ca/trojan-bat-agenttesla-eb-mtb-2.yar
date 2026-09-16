rule Trojan_BAT_AgentTesla_EB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 5f 47 71 63 61 70 } 		$a_01_1 = {61 63 6b 5f 75 67 69 } 		$a_01_2 = {66 78 73 6f 6c 69 63 79 5f 52 65 42 52 32 } 		$a_01_3 = {6e 75 62 73 5f 49 6e 74 61 74 63 68 61 } 		$a_01_4 = {4c 6f 63 74 5f 73 63 74 6d 67 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}