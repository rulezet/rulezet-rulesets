rule Trojan_Win32_EmotetCrypt_AR_MTB_4{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c3 99 f7 7c 24 2c 8b 44 24 28 8d 0c 2b 88 1c 0e 43 8a 14 02 88 11 8b 0d ?? ?? ?? ?? 3b d9 72 } 		$a_03_1 = {0f b6 14 2e 8a 06 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f1 8a 06 43 46 8a 0c 3a 88 04 3a 88 4e ff 8b 0d ?? ?? ?? ?? 3b d9 89 54 24 10 72 } 		$a_01_2 = {8b 44 24 24 8b 4c 24 14 8a 14 01 8b 4c 24 18 32 14 39 40 88 50 ff 89 44 24 24 ff 4c 24 10 75 } 		$a_81_3 = {51 79 69 6e 79 68 6a 6a 62 74 36 37 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*3) >=4
 
}