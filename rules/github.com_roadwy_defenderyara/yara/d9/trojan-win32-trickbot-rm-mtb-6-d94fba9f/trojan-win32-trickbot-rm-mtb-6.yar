rule Trojan_Win32_Trickbot_RM_MTB_6{
	meta:
		description = "Trojan:Win32/Trickbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 35 ?? ?? ?? ?? a0 ?? ?? ?? ?? 8a 14 0a 02 d0 8b 44 24 ?? 8a 1c 28 32 da 88 1c 28 8b 44 24 ?? 45 3b e8 72 } 		$a_81_1 = {78 34 4e 4c 73 67 78 53 23 2a 4a 77 47 39 5f 5f 68 54 49 21 6b 6f 52 71 63 36 37 65 4c 64 37 64 29 68 48 4f 72 58 6c 48 4c 38 54 58 2b 79 71 3e 32 4f 79 77 39 35 69 46 4d 43 79 49 3e 55 79 2b 4c 70 72 5a 28 21 6c 69 29 49 73 2b 4b 52 50 77 49 5a 7a 7a 5f 33 44 75 6e 3f 66 34 5a 55 71 5f 3f 56 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}