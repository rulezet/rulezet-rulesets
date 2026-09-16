rule Trojan_BAT_AgentTesla_NGE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 95 00 00 0a 26 73 ?? 00 00 0a 26 08 28 ?? 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 73 ?? 00 00 0a 26 73 ?? 00 00 0a 26 08 06 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 26 73 ?? 00 00 0a 26 73 ?? 00 00 0a 26 73 ?? 00 00 0a 26 07 73 ?? 00 00 0a } 		$a_01_1 = {57 77 30 78 34 5f 31 70 71 32 41 54 54 6a 72 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}