rule Trojan_BAT_AgentTesla_VN_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 19 8d ?? ?? ?? 01 25 16 7e ?? ?? ?? 04 a2 25 17 7e ?? ?? ?? 04 a2 25 18 72 ?? ?? ?? 70 a2 28 ?? ?? ?? 0a 26 16 0b 2b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}