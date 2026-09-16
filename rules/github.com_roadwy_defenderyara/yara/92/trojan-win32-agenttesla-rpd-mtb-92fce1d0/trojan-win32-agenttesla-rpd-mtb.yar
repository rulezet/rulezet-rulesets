rule Trojan_Win32_AgentTesla_RPD_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 10 8b 4d fc 03 4d e0 0f b6 11 81 ea ?? ?? ?? ?? 8b 45 fc 03 45 e0 88 10 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}