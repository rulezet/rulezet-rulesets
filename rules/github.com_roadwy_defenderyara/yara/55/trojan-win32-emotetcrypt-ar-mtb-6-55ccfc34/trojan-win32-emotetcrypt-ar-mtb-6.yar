rule Trojan_Win32_EmotetCrypt_AR_MTB_6{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 8d 34 3b 88 1c 30 8b c3 99 f7 7c 24 2c 8b 44 24 28 43 8a 14 02 88 16 8b 2d ?? ?? ?? ?? 3b dd } 		$a_01_1 = {0f b6 14 1f 03 54 24 10 8a 03 0f b6 c0 03 c2 33 d2 f7 f5 8a 03 46 43 8b ea 8a 14 29 88 04 29 88 53 ff 89 6c 24 10 } 		$a_01_2 = {03 54 24 14 8a 04 0a 8b 54 24 18 02 c3 32 04 2a 45 88 45 ff 8b 44 24 10 48 89 6c 24 24 89 44 24 10 } 		$a_81_3 = {64 72 74 66 66 44 57 45 55 46 45 55 46 55 57 45 47 46 55 59 42 47 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1) >=2
 
}