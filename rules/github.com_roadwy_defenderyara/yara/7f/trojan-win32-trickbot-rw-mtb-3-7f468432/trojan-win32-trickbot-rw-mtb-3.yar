rule Trojan_Win32_Trickbot_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 03 c6 f7 f7 8b f2 8a 04 2e 88 01 8b 44 24 ?? 88 1c 2e 8b 3d ?? ?? ?? ?? 40 41 3b c7 89 44 24 18 72 } 		$a_81_1 = {23 61 29 46 26 53 50 66 63 45 67 72 47 74 46 63 34 74 72 6a 79 35 4a 73 35 37 21 77 4d 41 6c 73 4c 3f 30 64 6c 4a 41 47 35 3e 62 53 47 72 62 4b 37 40 75 33 73 61 58 6c 6c 74 65 51 31 5e 2a 71 6a 57 2a 35 48 7a 26 44 56 50 50 69 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}