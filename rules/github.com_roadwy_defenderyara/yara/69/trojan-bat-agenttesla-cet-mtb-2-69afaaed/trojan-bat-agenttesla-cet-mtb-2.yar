rule Trojan_BAT_AgentTesla_CET_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5d 17 d6 28 ?? ?? ?? 0a da 13 04 07 11 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 09 17 d6 0d 09 90 09 0f 00 06 09 28 ?? ?? ?? 0a 08 09 08 6f ?? ?? ?? 0a } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}