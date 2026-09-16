rule Trojan_BAT_AgentTesla_R_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 25 16 28 ?? ?? ?? 06 9d 25 17 28 ?? ?? ?? 06 9d 25 28 ?? ?? ?? 06 73 ?? ?? ?? 0a [0-40] 2a } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}