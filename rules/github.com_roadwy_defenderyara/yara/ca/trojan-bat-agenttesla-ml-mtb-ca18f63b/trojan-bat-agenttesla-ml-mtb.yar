rule Trojan_BAT_AgentTesla_ML_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {13 04 11 04 14 17 8d ?? ?? 00 01 25 16 19 8d ?? ?? 00 01 25 16 7e ?? ?? 00 04 a2 25 17 7e ?? ?? 00 04 a2 25 18 72 ?? ?? 00 70 a2 a2 6f ?? ?? 00 0a 26 1f 17 8c ?? ?? 00 01 0a 2b 00 06 2a } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}