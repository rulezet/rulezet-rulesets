rule Trojan_BAT_AgentTesla_EAC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 01 13 05 38 ?? 00 00 00 11 01 11 02 11 01 11 03 91 9c 20 03 00 00 00 fe ?? 06 00 38 ?? ff ff ff 11 01 11 03 11 04 9c 38 ?? 00 00 00 11 03 17 59 13 03 20 02 00 00 00 7e ?? 06 00 04 7b ?? 06 00 04 39 ?? ff ff ff 26 20 02 00 00 00 38 ?? ff ff ff 11 01 11 02 91 13 04 38 ?? ff ff ff 11 02 17 58 13 02 20 00 00 00 00 7e } 		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}