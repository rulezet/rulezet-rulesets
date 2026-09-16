rule Trojan_BAT_AgentTesla_NHA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 1f 00 00 04 72 ?? ?? 00 70 73 ?? ?? 00 0a 28 ?? ?? 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 0a 6f ?? ?? 00 0a 73 ?? ?? 00 0a 25 6f ?? ?? 00 0a } 		$a_01_1 = {4c 49 4e 43 41 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}