rule Trojan_Win32_Trickbot_CM_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 3c 0b 33 d2 88 0c 38 8b c1 f7 74 24 ?? 8b 44 24 ?? 41 8a 14 02 88 17 8b 3d ?? ?? ?? ?? 3b cf 72 } 		$a_03_1 = {8a 19 0f be 14 08 8b c3 03 f2 25 ff 00 00 00 33 d2 03 c6 f7 f7 8b f2 8a 04 2e 88 01 8b 15 [0-12] 03 c2 8b 15 ?? ?? ?? ?? 03 c2 8d 14 ?? 8b c6 2b c2 88 1c 28 8b 44 24 ?? 8b 3d ?? ?? ?? ?? 40 41 3b c7 89 44 24 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}