rule Trojan_Win32_Qakbot_GC_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 02 8b 4d ?? 8d 94 01 ?? ?? ?? ?? 8b 45 ?? 89 10 8b 4d ?? 8b 11 81 ea ?? ?? ?? ?? 8b 45 ?? 89 10 8b e5 } 		$a_02_1 = {8b d0 33 d1 8b c2 8b ff c7 05 [0-30] 8b ff 01 05 ?? ?? ?? ?? 8b ff } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}