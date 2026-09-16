rule Trojan_BAT_AgentTesla_NLA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {12 02 22 00 00 61 43 11 00 58 6c 28 ?? ?? ?? 0a b7 28 ?? ?? ?? 0a 38 ?? ?? ?? ff 02 6f ?? ?? ?? 06 02 7b ?? ?? ?? 04 6c 02 7b ?? ?? ?? 04 6c 5b 28 ?? ?? ?? 0a } 		$a_01_1 = {41 75 6e 65 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}