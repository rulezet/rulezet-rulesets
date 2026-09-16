rule Backdoor_BAT_AgentTesla_MTB_3{
	meta:
		description = "Backdoor:BAT/AgentTesla!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {a2 25 17 11 04 7b ?? 00 00 04 a2 25 90 0a 50 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 0a 06 72 ?? ?? 00 70 6f ?? 00 00 0a 0b 07 72 ?? ?? 00 70 6f ?? 00 00 0a 0c 07 28 ?? 00 00 0a 0d 73 ?? 00 00 06 13 ?? 1f ?? 8d ?? 00 00 01 25 16 11 04 7b ?? 00 00 04 a2 25 17 11 04 7b ?? 00 00 04 a2 25 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}