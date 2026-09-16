rule Trojan_BAT_AgentTesla_MS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {25 17 19 8d ?? ?? 00 01 25 16 7e ?? ?? 00 04 a2 25 17 7e ?? ?? 00 04 a2 25 18 72 ?? ?? 00 70 a2 a2 14 14 14 17 28 ?? ?? 00 0a 26 1f } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}