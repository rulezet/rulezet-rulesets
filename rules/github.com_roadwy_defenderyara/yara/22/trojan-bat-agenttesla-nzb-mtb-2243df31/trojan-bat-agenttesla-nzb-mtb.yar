rule Trojan_BAT_AgentTesla_NZB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 17 58 13 01 ?? ?? ?? ?? 00 11 00 7e ?? ?? ?? 04 11 01 7e ?? ?? ?? 04 8e 69 5d 91 02 11 01 91 61 d2 6f ?? ?? ?? 0a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}