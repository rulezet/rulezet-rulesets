rule Trojan_BAT_AgentTesla_NZ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 03 17 58 ?? ?? ?? ?? ?? 5d 91 13 00 } 		$a_01_1 = {57 65 61 74 68 65 72 4f 62 73 65 72 76 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } 		$a_01_2 = {34 64 33 37 62 38 37 62 64 63 66 39 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}