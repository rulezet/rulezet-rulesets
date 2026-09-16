rule Trojan_BAT_AgentTesla_VN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0a 06 16 7e ?? ?? ?? 04 a2 06 17 7e ?? ?? ?? 04 a2 06 18 72 ?? ?? ?? 70 a2 03 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}