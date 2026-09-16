rule Trojan_Win32_Trickbot_A_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 74 ?? 8b 55 08 52 e8 ?? ?? ?? ?? 83 c4 04 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 0c 03 45 fc 8b 4d 08 8a 00 32 04 11 8b 4d 0c 03 4d fc 88 01 eb } 		$a_02_1 = {57 8b ec 8b c7 05 ?? ?? ?? ?? 68 f0 ff 00 00 89 45 04 59 8b d7 8b f7 8b c1 66 ad 85 c0 74 } 		$a_00_2 = {51 8b c6 8b 00 46 8b 0f 33 c8 8b c1 88 07 47 4b 58 8b c8 75 06 58 2b f0 50 8b d8 49 75 e2 } 	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}