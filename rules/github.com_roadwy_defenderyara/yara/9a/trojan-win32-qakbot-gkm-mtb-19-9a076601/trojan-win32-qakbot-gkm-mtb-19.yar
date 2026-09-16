rule Trojan_Win32_Qakbot_GKM_MTB_19{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c8 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? eb ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}