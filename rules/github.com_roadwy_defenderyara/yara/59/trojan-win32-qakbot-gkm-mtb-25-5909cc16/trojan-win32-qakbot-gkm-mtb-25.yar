rule Trojan_Win32_Qakbot_GKM_MTB_25{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b d8 01 5d ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? eb ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? 8b 45 ?? 8b 55 ?? 01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}