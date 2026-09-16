rule Trojan_BAT_AgentTesla_I_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 0a 06 16 72 ?? ?? ?? ?? a2 06 17 02 28 ?? ?? ?? 06 a2 06 18 7e ?? ?? ?? 04 a2 06 28 ?? ?? ?? 0a 00 06 73 ?? ?? ?? 06 0b 2a } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}