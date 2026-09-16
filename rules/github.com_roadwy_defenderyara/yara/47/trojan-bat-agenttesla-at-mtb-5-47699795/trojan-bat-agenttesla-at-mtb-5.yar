rule Trojan_BAT_AgentTesla_AT_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 4b 07 06 8e 69 5d 13 05 07 11 04 6f ?? ?? ?? 0a 5d 13 08 06 11 05 91 13 09 11 04 11 08 6f ?? ?? ?? 0a 13 0a 02 06 07 28 ?? ?? ?? 06 13 0b 02 11 09 11 0a 11 0b 28 ?? ?? ?? 06 13 0c 06 11 05 02 11 0c 28 ?? ?? ?? 06 9c 07 17 59 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}