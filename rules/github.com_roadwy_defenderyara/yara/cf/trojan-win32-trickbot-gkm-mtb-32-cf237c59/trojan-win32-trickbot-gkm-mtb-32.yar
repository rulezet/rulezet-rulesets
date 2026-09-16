rule Trojan_Win32_Trickbot_GKM_MTB_32{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b f0 81 fb 00 01 00 00 72 ?? ff 15 ?? ?? ?? ?? 8b 07 8b 48 ?? 8b 45 ?? 8a 14 31 8b 75 ?? 88 14 18 b8 01 00 00 00 03 c3 0f 80 ?? ?? ?? ?? 8b d8 eb } 		$a_02_1 = {0f bf c9 3b 4d ?? 7f ?? 8b 16 8b 42 ?? 8b 7a ?? 2b c7 33 d2 8a 14 08 8d 3c 08 8b 45 ?? 8a 14 02 8b 45 ?? 88 17 03 c8 eb } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}