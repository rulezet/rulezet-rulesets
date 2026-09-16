rule Trojan_BAT_AgentTesla_VN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 7e ?? ?? ?? 04 a2 25 17 02 7b ?? ?? ?? 04 a2 25 18 72 ?? ?? ?? 70 a2 0a 2b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}