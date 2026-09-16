rule Trojan_Win32_Trickbot_GKM_MTB_17{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 04 2f 88 04 3b 88 0c 2f 0f b6 04 3b 0f b6 c9 03 c1 33 d2 f7 35 ?? ?? ?? ?? 89 54 24 } 		$a_02_1 = {8a 14 3a 30 14 08 8b 4c 24 ?? 40 3b c1 89 44 24 ?? 0f 82 76 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}