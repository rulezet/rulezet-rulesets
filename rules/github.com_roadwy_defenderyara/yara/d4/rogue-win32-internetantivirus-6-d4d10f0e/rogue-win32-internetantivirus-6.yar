rule Rogue_Win32_InternetAntivirus_6{
	meta:
		description = "Rogue:Win32/InternetAntivirus,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {c6 03 e9 47 89 2f 8d 44 24 04 50 8b 44 24 08 50 6a 05 53 } 		$a_03_1 = {50 6a 00 6a 2a e8 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 6a 00 e8 } 		$a_03_2 = {8b 03 50 8d 85 ?? ?? ff ff 50 e8 ?? ?? ?? ?? 85 c0 75 14 ba ?? ?? ?? ?? 8b 85 ?? ?? ff ff e8 } 		$a_00_3 = {5f 52 6f 6f 74 6b 69 74 4d 75 74 65 78 00 } 		$a_00_4 = {72 65 67 65 64 69 74 2e 65 78 65 00 74 6f 74 61 6c 63 6d 64 2e 65 78 65 00 } 		$a_03_5 = {50 6a 00 6a 02 e8 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 56 e8 ?? ?? ?? ?? 56 e8 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}