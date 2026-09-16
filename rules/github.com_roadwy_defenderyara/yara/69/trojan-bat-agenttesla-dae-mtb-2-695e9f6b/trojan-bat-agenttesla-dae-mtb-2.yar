rule Trojan_BAT_AgentTesla_DAE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 04 06 11 04 28 ?? ?? ?? 06 07 da 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 0a 00 09 17 d6 0d 09 08 28 ?? ?? ?? 06 fe 04 13 05 11 05 2d c8 } 		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } 		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}