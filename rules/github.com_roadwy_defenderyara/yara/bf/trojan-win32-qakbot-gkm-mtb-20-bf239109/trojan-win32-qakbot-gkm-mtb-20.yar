rule Trojan_Win32_Qakbot_GKM_MTB_20{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73 } 		$a_02_1 = {2b d8 8b 45 ?? 89 18 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}