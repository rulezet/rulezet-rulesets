rule Trojan_BAT_AgentTesla_RPZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 04 5d 13 07 11 06 11 05 5d 13 08 11 06 17 58 11 04 5d 13 09 07 11 07 91 08 11 08 91 61 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}