rule Trojan_BAT_AgentTesla_AAT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 03 6f ?? 00 00 0a 16 03 6f ?? 00 00 0a 0a 12 00 28 ?? 00 00 0a 73 ?? 00 00 0a a2 25 17 03 6f ?? 00 00 0a 17 03 6f ?? 00 00 0a 0a 12 00 28 ?? 00 00 0a 73 ?? 00 00 0a a2 25 18 03 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}