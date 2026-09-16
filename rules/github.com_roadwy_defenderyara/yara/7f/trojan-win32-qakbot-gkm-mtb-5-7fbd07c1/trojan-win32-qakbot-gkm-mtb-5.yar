rule Trojan_Win32_Qakbot_GKM_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 f8 83 c6 43 8a 04 2a 88 02 8b c7 2b c1 42 83 c0 43 89 54 24 ?? 0f b7 c8 2b ce 83 c1 40 39 35 ?? ?? ?? ?? 77 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}