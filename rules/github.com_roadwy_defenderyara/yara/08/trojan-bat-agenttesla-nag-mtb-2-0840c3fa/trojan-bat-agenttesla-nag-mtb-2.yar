rule Trojan_BAT_AgentTesla_NAG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 72 23 00 00 70 6f ?? ?? ?? 0a 00 02 02 fe ?? ?? ?? ?? 06 73 ?? ?? ?? 0a 28 ?? ?? ?? 0a 00 02 16 28 ?? ?? ?? 0a 00 2a } 		$a_01_1 = {47 50 54 34 5f 56 32 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}