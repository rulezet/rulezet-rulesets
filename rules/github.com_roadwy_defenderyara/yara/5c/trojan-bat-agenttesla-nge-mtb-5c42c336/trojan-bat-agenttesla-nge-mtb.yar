rule Trojan_BAT_AgentTesla_NGE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 10 8d 5b 00 00 01 13 14 11 09 28 ?? ?? 00 0a 16 11 14 16 1a 28 ?? ?? 00 0a 11 0a 28 ?? ?? 00 0a 16 11 14 1a 1a 28 ?? ?? 00 0a 11 0b 28 ?? ?? 00 0a 16 11 14 1e 1a 28 ?? ?? 00 0a } 		$a_01_1 = {50 00 65 00 72 00 66 00 65 00 63 00 74 00 53 00 63 00 72 00 69 00 70 00 74 00 20 00 31 00 39 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}