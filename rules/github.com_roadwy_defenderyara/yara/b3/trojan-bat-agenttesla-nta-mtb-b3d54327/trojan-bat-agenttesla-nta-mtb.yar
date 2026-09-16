rule Trojan_BAT_AgentTesla_NTA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 28 18 00 00 06 26 7e ?? ?? ?? 04 18 6f ?? ?? ?? 0a 00 02 28 ?? ?? ?? 06 0a 2b 00 06 2a } 		$a_01_1 = {53 70 6c 61 73 68 54 65 73 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}