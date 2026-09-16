rule Trojan_BAT_AgentTesla_GJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {a2 25 17 7e ?? ?? ?? 0a a2 25 18 11 06 a2 25 19 17 8c ?? ?? ?? 01 a2 13 0a 11 09 11 07 } 		$a_80_1 = {2f 2f 74 72 61 6e 73 66 65 72 2e 73 68 } 	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}