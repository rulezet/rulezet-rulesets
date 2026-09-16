rule Trojan_BAT_AgentTesla_NAN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 d0 31 00 00 01 28 ?? 00 00 0a 06 17 8d ?? 00 00 01 25 16 d0 ?? 00 00 1b 28 ?? 00 00 0a a2 28 ?? 00 00 0a 14 17 8d ?? 00 00 01 25 16 28 ?? 00 00 06 a2 6f ?? 00 00 0a } 		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 32 31 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}