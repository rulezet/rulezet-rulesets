rule TrojanDownloader_Win32_Vundo_HIZ_2{
	meta:
		description = "TrojanDownloader:Win32/Vundo.HIZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 10 8b 48 28 85 c9 74 14 a1 ?? ?? 00 10 6a 00 03 c8 6a ?? 50 89 0d ?? ?? 00 10 ff d1 c3 } 		$a_03_1 = {31 48 04 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 31 48 08 } 		$a_00_2 = {03 03 ff e0 83 7c 24 08 01 } 		$a_01_3 = {0f b7 55 f4 33 4d f4 33 c2 5f 5e 66 85 c9 75 05 b8 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}