rule Trojan_Win32_Trickbot_GKM_MTB_10{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b fa 8a 04 0f 88 04 0e 88 1c 0f 0f b6 04 0e 0f b6 d3 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 ?? 8a 14 0a 30 54 28 ?? 3b 6c 24 1c 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}