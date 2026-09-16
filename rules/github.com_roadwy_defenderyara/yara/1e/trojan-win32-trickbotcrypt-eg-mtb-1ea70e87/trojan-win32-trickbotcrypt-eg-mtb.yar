rule Trojan_Win32_TrickBotCrypt_EG_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 02 8b 4d ?? 8b 11 8b 4d ?? 0f b6 14 11 03 15 ?? ?? ?? ?? 8b 4d ?? 0f b6 04 01 33 c2 8b 4d ?? 8b 11 8b 4d ?? 88 04 11 } 		$a_81_1 = {4d 34 63 78 31 28 42 6d 58 3e 50 67 53 4b 38 3e 24 3f 39 25 6a 4b 40 52 55 25 30 59 59 25 49 5f 68 71 67 51 48 57 67 3c 24 40 6b 28 24 29 69 4d 36 33 40 58 77 2b 31 7a 78 72 4a 2b 6b 29 37 35 21 77 79 58 44 44 34 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}