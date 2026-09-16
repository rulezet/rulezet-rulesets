rule Worm_Win32_Dorkbot_I_2{
	meta:
		description = "Worm:Win32/Dorkbot.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 4d 5a 00 00 74 05 e9 7c 01 00 00 8b 0d ?? ?? ?? ?? 8b 55 08 03 51 3c 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 81 38 50 45 00 00 74 05 } 		$a_01_1 = {74 13 8b 4d fc 03 4d f8 0f be 11 f7 d2 8b 45 fc 03 45 f8 88 10 eb 92 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}