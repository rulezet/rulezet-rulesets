rule Trojan_BAT_AgentTesla_R_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b5 13 04 17 0c 2b 25 07 09 02 08 17 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 61 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}