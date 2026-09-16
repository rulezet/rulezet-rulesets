rule SoftwareBundler_Win32_Ogimant_3{
	meta:
		description = "SoftwareBundler:Win32/Ogimant,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {8d 5a d0 80 fb 09 77 1b 8d 04 80 0f be d2 8d 44 42 d0 0f b6 11 83 c1 01 84 d2 75 e4 eb 05 } 		$a_03_1 = {29 c2 8b 0d ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 32 0c 03 88 4c 16 ff 83 e8 01 83 f8 ff 75 dd } 		$a_03_2 = {29 c1 8b 1d ?? ?? ?? ?? 32 1c 02 88 5c 0e ff 83 e8 01 83 f8 ff 75 e3 } 		$a_01_3 = {0f b6 55 e7 31 ca 88 10 } 		$a_01_4 = {0f b6 45 e7 31 d0 88 03 } 		$a_03_5 = {8b 50 28 8b 45 ?? 85 d2 74 ?? 03 55 ?? 74 ?? c7 44 24 08 00 00 00 00 c7 44 24 04 01 00 00 00 8b 4d ?? 89 0c 24 ff d2 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}