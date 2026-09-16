rule Trojan_BAT_AgentTesla_VN_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 9a 0a 06 14 19 8d ?? ?? ?? 01 25 16 7e ?? ?? ?? 04 a2 25 17 7e ?? ?? ?? 04 a2 25 18 72 ?? ?? ?? 70 a2 0b 07 6f ?? ?? ?? 0a 26 2a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}