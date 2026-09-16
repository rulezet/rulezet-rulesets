rule Trojan_Win32_Trickbot_VSK_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.VSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_00_0 = {8a 19 8b 45 ec 89 c1 81 c1 01 00 00 00 89 4d ec 88 18 8b 45 d4 8b 4d ac 01 c8 89 45 d4 eb } 		$a_00_1 = {8b c1 33 d2 bd 3f 00 00 00 f7 f5 8a 04 1a 8a 14 31 32 d0 88 14 31 41 3b cf 75 } 		$a_00_2 = {66 8b 75 d6 66 81 f6 25 79 66 89 75 d6 80 f2 4b 88 55 cb 8b 45 d0 05 ff ff ff ff 89 45 d0 eb } 		$a_02_3 = {8b 4d d0 03 4d d8 0f be 19 e8 ?? ?? ?? ?? 33 d8 8b 55 d0 03 55 d8 88 1a eb } 		$a_02_4 = {8b 4c 24 70 8b 54 24 18 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b f7 c1 ee 05 03 74 24 64 03 d9 03 d7 33 da 81 3d ?? ?? ?? ?? 72 07 00 00 75 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_02_3  & 1)*2+(#a_02_4  & 1)*2) >=2
 
}