rule Trojan_BAT_AgentTesla_MM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {a2 25 17 7e ?? ?? 00 04 a2 25 18 72 ?? ?? 00 70 a2 0a 28 ?? ?? 00 06 16 28 ?? ?? 00 06 28 ?? ?? 00 0a 06 28 ?? ?? 00 06 00 2a 90 09 07 00 25 16 7e ?? ?? 00 04 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}