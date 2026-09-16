rule Trojan_BAT_AgentTesla_NR_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 02 26 16 72 ?? ?? ?? 70 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 } 		$a_01_1 = {44 00 6e 00 45 00 61 00 7a 00 } 		$a_01_2 = {44 6e 45 61 7a 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}