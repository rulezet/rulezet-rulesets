rule Trojan_Win32_Trickbot_GKM_MTB_24{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b df 7e ?? 8b 4c 24 ?? 8d 4c 19 ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c3 7c ?? 8d 43 ?? c6 83 ?? ?? ?? ?? 00 83 f8 3e 7d } 		$a_00_1 = {52 43 72 42 4b 63 6f 21 23 62 6f 44 4c 30 44 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}