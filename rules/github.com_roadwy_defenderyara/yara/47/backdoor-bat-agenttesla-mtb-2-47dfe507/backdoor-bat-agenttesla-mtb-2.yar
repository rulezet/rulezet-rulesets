rule Backdoor_BAT_AgentTesla_MTB_2{
	meta:
		description = "Backdoor:BAT/AgentTesla!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 00 06 13 05 08 72 ?? 00 00 70 90 0a 50 00 72 ?? 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 0c 07 ?? ?? ?? ?? ?? 72 ?? 00 00 70 28 ?? 00 00 06 ?? ?? ?? ?? ?? 28 ?? 00 00 06 0d 08 72 ?? 00 00 70 28 ?? 00 00 06 13 04 08 72 ?? 00 00 70 28 ?? 00 00 06 13 05 08 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}