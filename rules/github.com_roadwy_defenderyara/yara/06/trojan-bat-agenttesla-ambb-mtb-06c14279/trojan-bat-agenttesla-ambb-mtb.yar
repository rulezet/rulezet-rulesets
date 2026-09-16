rule Trojan_BAT_AgentTesla_AMBB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0a 12 00 28 ?? 00 00 06 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 28 ?? 00 00 06 28 ?? 00 00 06 2a } 		$a_03_1 = {6f 25 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 2a } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}