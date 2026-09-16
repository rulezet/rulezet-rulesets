rule Trojan_Win32_AgentTesla_A_MTB_2{
	meta:
		description = "Trojan:Win32/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {64 ff 30 64 89 20 ff 05 ?? ?? ?? 00 75 ?? 83 3d ?? ?? ?? 00 00 74 0a a1 ?? ?? ?? 00 e8 } 		$a_02_1 = {8b c7 8b de 8b d3 90 05 10 01 90 e8 ?? ?? ?? ?? 90 05 10 01 90 46 90 05 10 01 90 81 fe ?? ?? 00 00 75 } 		$a_02_2 = {8b c8 03 ca 8b c2 b2 ?? 32 90 90 ?? ?? ?? 00 88 11 c3 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}