rule Trojan_Win32_TrickBot_RT_MTB_8{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c1 f7 35 ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? 8b ?? ?? 8d 0c 02 8a c3 f6 eb 8b ?? ?? 8a 1c 33 2a d8 30 19 42 3b ?? ?? 89 ?? ?? 72 } 		$a_81_1 = {5f 4b 45 72 47 5a 30 32 40 3f 55 56 4a 45 52 3e 37 2b 48 50 58 68 6e 4b 4e 32 6d 51 65 24 75 23 6e 62 76 63 30 33 4c 59 59 51 3e 57 29 73 5f 24 5e 71 28 4a 29 39 57 59 35 4c 4a 36 42 5a 76 3f 59 4b 6d 36 67 66 2a 7a 71 72 33 6b 68 43 5f 4d 29 74 24 69 38 78 49 40 78 23 6c 76 67 56 4a 5e 6d 55 47 73 32 51 35 72 52 29 68 59 65 46 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}