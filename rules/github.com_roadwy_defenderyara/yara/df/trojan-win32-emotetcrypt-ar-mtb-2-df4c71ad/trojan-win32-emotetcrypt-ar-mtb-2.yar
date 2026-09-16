rule Trojan_Win32_EmotetCrypt_AR_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 2b 8a 03 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f1 8a 03 47 43 8a 0c 32 88 04 32 88 4b ff 8b 0d ?? ?? ?? ?? 3b f9 89 54 24 10 } 		$a_01_1 = {8b 44 24 10 8b 4c 24 18 8a 14 01 8b 4c 24 1c 32 14 31 40 88 50 ff 89 44 24 10 ff 4c 24 14 } 		$a_81_2 = {4c 39 67 66 65 66 64 54 54 52 76 68 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=2
 
}