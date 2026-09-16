rule Trojan_Win32_Trickbot_GKM_MTB_4{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c8 0f b6 04 37 89 55 ?? 0f b6 d3 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 32 30 01 ff 45 ?? 8b 45 ?? 3b 45 ?? 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}