rule Trojan_Win32_Trickbot_GKM_MTB_11{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 0f b6 04 37 03 c1 f7 35 ?? ?? ?? ?? 8b da ff 15 ?? ?? ?? ?? 8b 45 ?? 8b 4d ?? 8a 14 33 03 c1 30 10 41 3b 4d ?? 89 4d ?? 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}