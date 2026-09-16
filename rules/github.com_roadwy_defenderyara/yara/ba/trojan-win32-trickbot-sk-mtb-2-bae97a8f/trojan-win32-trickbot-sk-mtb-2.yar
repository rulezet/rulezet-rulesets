rule Trojan_Win32_Trickbot_SK_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 40 68 ?? ?? 00 00 ff 15 ?? ?? 00 10 83 3d ?? ?? 00 10 00 74 ec c7 45 ?? 57 61 6e 74 c7 45 ?? 52 65 6c 65 c7 45 ?? 61 73 65 00 ff 35 ?? ?? 00 10 6a 00 6a 00 6a 00 6a 00 8d 45 ?? 50 ff 35 ?? ?? 00 10 ff 15 ?? ?? 00 10 } 		$a_00_1 = {51 8b c6 46 8b 0f 8b 00 33 c8 58 88 0f 47 4b 8b c8 75 06 58 2b f0 50 8b d8 49 75 e4 59 58 59 5e 5f 5b } 	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}