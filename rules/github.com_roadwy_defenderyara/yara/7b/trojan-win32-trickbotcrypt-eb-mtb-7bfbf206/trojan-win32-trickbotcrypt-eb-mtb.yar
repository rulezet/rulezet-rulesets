rule Trojan_Win32_TrickBotCrypt_EB_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e8 3b 4d f4 73 ?? 8b 55 e8 0f b6 02 0f b6 4d e7 33 c1 8b 55 e8 2b 55 08 0f b6 ca 81 e1 e0 00 00 00 33 c1 8b 55 e8 88 02 8b 45 e8 03 45 fc 89 45 e8 eb cb } 		$a_81_1 = {3c 64 5a 34 4f 48 33 57 3e 4d 21 68 59 28 5f 34 5e 44 76 39 37 37 62 76 56 39 45 38 55 3e 26 46 39 5e 79 40 69 6d 72 3c 29 26 67 2b 48 29 39 54 6e 4a 77 44 66 5f 2a 33 69 44 36 46 31 67 26 5e 2a 4d 4c 70 4f 31 39 48 4e 53 70 41 32 51 5f 3f 65 3e 5e 70 21 6f 65 39 64 76 2a 45 6c 76 39 50 37 3f 70 40 } 	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*5) >=5
 
}