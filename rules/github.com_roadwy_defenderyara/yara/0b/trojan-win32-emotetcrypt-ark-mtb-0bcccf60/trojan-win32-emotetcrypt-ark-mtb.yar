rule Trojan_Win32_EmotetCrypt_ARK_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.ARK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {f7 f1 8b 2d ?? ?? ?? ?? 8b fa 0f b6 04 37 03 c3 33 d2 f7 f1 8a 0c 37 8b da 8a 04 33 88 0c 33 88 04 37 0f b6 14 33 } 		$a_03_1 = {8b 45 08 8b 4d f8 8b 15 ?? ?? ?? ?? 03 c1 0f b6 4d ff 8a 0c 11 30 08 ff 45 f8 8b 45 f8 3b 45 0c 7c } 		$a_03_2 = {0f b6 13 03 c2 99 b9 e3 03 00 00 f7 f9 a1 ?? ?? ?? ?? 45 0f b6 d2 8a 0c 02 30 4d ff 83 6c 24 14 01 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}