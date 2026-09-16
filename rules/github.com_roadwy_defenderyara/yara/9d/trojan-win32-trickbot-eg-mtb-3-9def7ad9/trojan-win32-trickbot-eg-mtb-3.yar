rule Trojan_Win32_Trickbot_EG_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 55 e8 0f b6 02 0f b6 4d e7 33 c1 8b 55 e8 2b 55 08 0f b6 ca 81 e1 e0 00 00 00 33 c1 8b 55 e8 88 02 } 		$a_03_1 = {8b 55 ec 83 c2 01 89 55 ec 8b 45 ec 3b 45 fc 0f 8d ?? ?? ?? ?? 8b 4d f0 03 4d ec 0f be 11 81 f2 e0 00 00 00 88 55 e7 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}