rule Trojan_BAT_AgentTesla_NZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {48 52 48 41 35 34 34 37 45 38 35 4e 56 34 35 35 51 37 37 4f 54 41 78 } 		$a_01_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } 		$a_01_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } 	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}