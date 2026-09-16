rule Trojan_BAT_AgentTesla_GN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 06 14 19 8d ?? ?? ?? 01 25 16 7e ?? ?? ?? 04 a2 25 17 7e ?? ?? ?? ?? a2 25 18 72 ?? ?? ?? 70 a2 14 6f ?? ?? ?? 0a [0-10] 2a } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}