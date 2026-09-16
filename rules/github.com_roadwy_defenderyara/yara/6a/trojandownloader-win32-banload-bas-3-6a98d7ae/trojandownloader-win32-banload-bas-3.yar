rule TrojanDownloader_Win32_Banload_BAS_3{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 83 6c 03 00 00 ?? 00 00 00 8d 83 70 03 00 00 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 83 74 03 00 00 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 83 78 03 00 00 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 55 } 		$a_01_1 = {8d 55 f7 b9 01 00 00 00 8b 45 fc 8b 38 ff 57 0c 8b ce 0f b7 45 f4 d3 e8 f6 d0 30 45 f7 8d 55 f7 b9 01 00 00 00 8b 45 f8 8b 38 ff 57 10 } 		$a_03_2 = {0f b6 44 30 ff 33 c3 89 45 ?? 3b 7d ?? 7c 0f 8b 45 ?? 05 ff 00 00 00 2b c7 89 45 ?? eb 03 29 7d ?? 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 8b 55 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}