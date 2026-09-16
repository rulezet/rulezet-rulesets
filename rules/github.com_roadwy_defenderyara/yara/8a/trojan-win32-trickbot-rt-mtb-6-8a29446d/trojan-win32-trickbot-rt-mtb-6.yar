rule Trojan_Win32_TrickBot_RT_MTB_6{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c2 2b 05 ?? ?? ?? ?? 8b 55 ?? 8b 75 ?? 8a 0c 0a 32 0c 06 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 75 } 		$a_81_1 = {51 67 3c 47 32 4f 6c 71 2b 25 78 61 48 79 53 6d 7a 57 6f 68 45 48 6b 65 29 42 2a 43 32 36 41 69 4b 28 50 4c 2a 62 38 33 30 36 43 40 3c 6f 30 38 50 31 72 30 7a 50 6a 50 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}