rule Trojan_Win32_Qakbot_GKM_MTB_14{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b d8 01 5d ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? e9 ?? ?? ?? ?? 33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 0f 83 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}