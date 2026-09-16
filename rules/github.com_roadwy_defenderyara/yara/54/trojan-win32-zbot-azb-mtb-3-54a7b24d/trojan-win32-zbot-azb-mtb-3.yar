rule Trojan_Win32_Zbot_AZB_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.AZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {a6 8a 5b 01 c3 45 60 88 5d 0b c3 a5 ?? 3a 5a 01 c3 56 31 83 ?? ?? ?? ?? 3a f2 42 c3 5c 33 d2 c3 42 5f 1b d2 c3 } 		$a_03_1 = {4a 96 83 f8 02 c3 30 88 ?? ?? ?? ?? 83 e8 03 c3 d7 37 0f b6 09 c3 a9 c1 e0 08 c3 b4 14 03 c1 } 		$a_01_2 = {77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 45 00 50 00 61 00 2e 00 65 00 78 00 65 00 2e 00 62 00 61 00 74 00 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}