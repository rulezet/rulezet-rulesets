rule Trojan_BAT_AgentTesla_VN_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 28 ?? ?? ?? 06 9d 25 17 28 ?? ?? ?? 06 9d 25 18 1f ?? 9d 25 19 1f ?? 9d 80 ?? ?? ?? 04 2a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}