rule Trojan_Win32_Trickbot_GKM_MTB_20{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 8a 04 37 81 e1 ff 00 00 00 03 c1 f7 35 ?? ?? ?? ?? 89 54 24 ?? ff 15 ?? ?? ?? ?? 8b 54 24 ?? 8b 44 24 ?? 8a 0c 32 8a 14 28 32 d1 88 14 28 8b 44 24 ?? 45 3b e8 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}