rule Trojan_BAT_AgentTesla_NAD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 1a 00 00 06 25 28 ?? 00 00 06 75 ?? 00 00 01 6f ?? 00 00 0a 16 a3 ?? 00 00 01 28 ?? 00 00 06 } 		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 34 31 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}