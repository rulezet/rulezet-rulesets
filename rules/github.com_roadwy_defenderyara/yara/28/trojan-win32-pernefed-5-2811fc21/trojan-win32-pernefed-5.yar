rule Trojan_Win32_Pernefed_5{
	meta:
		description = "Trojan:Win32/Pernefed,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 "
		
	strings :
		$a_03_0 = {8a 54 3a ff 80 f2 ff e8 ?? ?? ?? ?? 8b 55 f8 8b c6 e8 ?? ?? ?? ?? 47 4b 75 e0 } 		$a_03_1 = {8a 54 0a ff 80 f2 ff e8 ?? ?? ?? ?? 8b 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? ff 45 ?? ff 4d ?? 75 d5 } 		$a_03_2 = {8a 54 38 ff 8a 04 1e e8 ?? ?? ?? ?? 88 04 1e 8b 45 fc 8a 44 38 ff 30 04 1e 43 ff 4d ?? 75 de } 		$a_01_3 = {8f 9b 99 91 9b 8d 00 } 		$a_01_4 = {8f 9b 92 90 91 96 8b 90 8d 00 } 		$a_01_5 = {bb 9a 99 9a 91 9b 9a 8d } 		$a_01_6 = {cc e0 db ff ff ff dd eb e6 78 ad 9f 02 63 4e 02 6e 3d 02 7c 26 24 8e 42 ff ff ff ff ff ff 24 76 } 		$a_01_7 = {2d 16 01 00 00 48 50 8b 45 ?? 2d 5e 01 00 00 90 09 11 00 6a 00 6a 30 e8 ?? ?? ?? ?? 68 00 00 40 00 8b 45 ?? } 		$a_01_8 = {8a 45 08 2c 01 72 77 0f 84 99 00 00 00 fe c8 74 09 fe c8 74 39 e9 b2 00 00 00 ba } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=3
 
}