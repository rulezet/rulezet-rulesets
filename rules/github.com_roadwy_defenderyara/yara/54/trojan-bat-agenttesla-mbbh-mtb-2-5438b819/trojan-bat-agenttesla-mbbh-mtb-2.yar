rule Trojan_BAT_AgentTesla_MBBH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 11 ?? 11 ?? 11 ?? 8e 69 5d 91 11 ?? 11 ?? 1f ?? 5d 91 61 7e ?? ?? ?? 04 28 ?? ?? ?? 06 11 ?? 11 ?? 17 58 11 ?? 8e 69 5d 91 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}