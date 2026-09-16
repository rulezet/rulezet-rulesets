rule Trojan_BAT_AgentTesla_NMA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 31 00 00 0a 2b d5 28 ?? 00 00 06 2b d5 6f ?? 00 00 0a 2b d0 28 ?? 00 00 0a 2b cb 0b 2b ca 07 2b c9 07 2b c9 28 ?? 00 00 0a } 		$a_01_1 = {50 77 6a 68 68 69 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}