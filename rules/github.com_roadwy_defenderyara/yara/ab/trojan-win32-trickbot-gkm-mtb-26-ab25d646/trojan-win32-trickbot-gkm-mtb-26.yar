rule Trojan_Win32_Trickbot_GKM_MTB_26{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d2 f7 f1 8b 45 ?? 89 55 ?? 8d 0c 1a 8a 14 1a 88 14 18 8a 55 ?? 88 11 0f b6 04 18 0f b6 ca 03 c1 33 d2 f7 35 ?? ?? ?? ?? 89 55 } 		$a_02_1 = {03 c1 8a 14 1a 30 10 41 3b 4d ?? 89 4d ?? 72 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}