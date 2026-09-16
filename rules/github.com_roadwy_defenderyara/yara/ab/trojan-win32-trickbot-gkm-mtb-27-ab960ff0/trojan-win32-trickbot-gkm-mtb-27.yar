rule Trojan_Win32_Trickbot_GKM_MTB_27{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f0 81 fb 00 01 00 00 72 ?? ff 15 ?? ?? ?? ?? 8b 0f 8b 51 ?? 8b 4d ?? 8a 04 32 8b 75 ?? 88 04 19 b8 01 00 00 00 03 c3 0f 80 ?? ?? ?? ?? 8b d8 eb ?? 8b 17 52 6a 01 ff 15 ?? ?? ?? ?? 66 83 c6 02 89 85 ?? ?? ?? ?? 0f 80 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}