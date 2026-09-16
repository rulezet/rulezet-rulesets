rule Trojan_BAT_AgentTesla_MP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {1c 9a 0c 08 19 8d ?? ?? 00 01 25 16 7e ?? ?? 00 04 a2 25 17 7e ?? ?? 00 04 a2 25 18 72 ?? ?? 00 70 a2 28 ?? ?? 00 0a 26 1f 17 8c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}