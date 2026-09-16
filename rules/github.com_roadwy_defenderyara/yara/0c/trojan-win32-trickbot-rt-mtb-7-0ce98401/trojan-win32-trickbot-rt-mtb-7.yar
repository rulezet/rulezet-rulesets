rule Trojan_Win32_TrickBot_RT_MTB_7{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c3 03 f2 25 ff 00 00 00 33 d2 03 c6 f7 f7 8b f2 8a 04 2e 88 01 8b 44 24 ?? 88 1c 2e 8b 3d ?? ?? ?? ?? 40 41 3b c7 89 44 24 ?? 72 } 		$a_81_1 = {28 33 28 61 6e 39 31 58 70 37 70 4e 26 51 47 3c 66 4b 43 5e 48 74 42 26 74 73 69 37 72 4c 35 29 62 74 74 70 57 6a 44 6c 73 32 38 4a 64 59 28 4a 4e 76 45 69 53 61 57 62 72 51 55 5a 6b 54 38 4a 79 41 3c 48 62 46 5a 78 28 6a 4e 4b 4e 43 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}