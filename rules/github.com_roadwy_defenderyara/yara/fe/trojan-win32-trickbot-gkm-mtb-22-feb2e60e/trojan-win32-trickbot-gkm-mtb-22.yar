rule Trojan_Win32_Trickbot_GKM_MTB_22{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b fa 8b 54 24 ?? 81 e2 ff 00 00 00 8a 04 0f 88 04 0e 33 c0 88 1c 0f 8a 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 ?? 8a 1c 28 8a 14 0a 32 da 88 1c 28 8b 44 24 ?? 45 3b e8 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}