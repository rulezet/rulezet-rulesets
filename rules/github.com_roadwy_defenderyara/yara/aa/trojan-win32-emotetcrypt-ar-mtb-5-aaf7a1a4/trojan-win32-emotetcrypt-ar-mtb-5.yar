rule Trojan_Win32_EmotetCrypt_AR_MTB_5{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 54 24 20 88 14 0f 88 04 0e 0f b6 14 0e 0f b6 04 0f 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 8b 54 24 14 32 04 1a 43 88 43 ff ff 4c 24 10 } 		$a_81_1 = {79 36 69 74 68 67 72 68 68 79 74 74 } 		$a_81_2 = {63 3a 5c 55 73 65 72 73 5c 44 6f 64 6f 5c 44 6f 77 6e 6c 6f 61 64 73 5c 57 65 62 50 61 67 65 53 6e 61 70 53 68 6f 74 5c 52 65 6c 65 61 73 65 5c 57 65 62 50 61 67 65 53 6e 61 70 53 68 6f 74 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}