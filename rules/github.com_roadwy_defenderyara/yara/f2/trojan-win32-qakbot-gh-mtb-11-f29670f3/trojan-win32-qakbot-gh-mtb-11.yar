rule Trojan_Win32_Qakbot_GH_MTB_11{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d ?? ?? 00 00 8b 4d 08 89 01 5e 8b e5 5d c3 } 		$a_02_1 = {03 45 fc 88 1c 30 8b 55 f8 83 c2 01 89 55 f8 eb ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 5e 5b 8b e5 5d c3 } 		$a_02_2 = {89 11 5d c3 90 0a 28 00 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 } 		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}