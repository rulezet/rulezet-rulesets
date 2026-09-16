rule TrojanDownloader_Win32_Sinowal_A_3{
	meta:
		description = "TrojanDownloader:Win32/Sinowal.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 1f 8b 55 ?? 03 55 ?? 0f be 02 83 c0 ?? 8b 4d ?? 03 4d ?? 88 01 8b 55 ?? 83 c2 01 89 55 ?? eb d4 } 		$a_03_1 = {75 09 c7 45 fc fe ff ff ff eb 71 68 ?? ?? ?? ?? 8b 4d ?? 51 ff 15 ?? ?? ?? ?? 89 45 ?? 83 7d ?? 00 74 38 } 		$a_01_2 = {e9 34 01 00 00 0f b7 45 14 3d bb 01 00 00 75 0c 8b 4d f8 81 c9 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}