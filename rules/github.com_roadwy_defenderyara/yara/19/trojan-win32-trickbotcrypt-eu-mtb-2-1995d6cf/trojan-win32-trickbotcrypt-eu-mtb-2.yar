rule Trojan_Win32_TrickBotCrypt_EU_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c8 8b 45 ?? 0f af cb 03 4d f0 03 c1 8a 0c 3a 02 0d ?? ?? ?? ?? 30 08 ff 45 f0 8b 45 f0 3b 45 ?? 0f 82 90 09 03 00 89 55 } 		$a_81_1 = {40 66 47 75 2b 6d 6e 64 24 30 25 4f 69 35 4b 33 40 41 64 40 76 58 67 42 48 54 51 7a 21 6c 70 4b 79 61 34 42 47 64 75 70 78 6c 28 35 71 44 38 77 53 50 65 46 29 54 6d 79 66 6b 38 65 69 70 58 76 23 64 54 33 28 42 6d 55 49 28 59 39 30 29 72 73 57 54 51 28 78 2b 70 47 63 58 62 44 30 51 77 6d 51 23 79 6f 6a 71 56 3f 4d 31 34 34 7a 54 25 5e 48 68 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}