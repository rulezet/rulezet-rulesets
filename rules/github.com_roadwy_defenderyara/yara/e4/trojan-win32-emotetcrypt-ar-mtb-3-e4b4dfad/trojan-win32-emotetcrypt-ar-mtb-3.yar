rule Trojan_Win32_EmotetCrypt_AR_MTB_3{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 8d 2c 3b 88 1c 28 8b c3 99 f7 7c 24 2c 8b 44 24 28 43 3b de 8a 14 02 88 55 00 } 		$a_01_1 = {33 d2 f7 f6 8a 03 43 8b fa 8a 14 0f 88 04 0f 8b 44 24 14 88 53 ff 48 89 7c 24 10 89 44 24 14 } 		$a_01_2 = {88 14 0f 88 04 29 0f b6 14 29 0f b6 04 0f 03 c2 33 d2 f7 f6 8a 04 0a 8b 54 24 18 32 04 1a 43 88 43 ff ff 4c 24 14 } 		$a_81_3 = {42 35 36 77 72 67 37 51 72 78 74 74 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_81_3  & 1)*1) >=3
 
}