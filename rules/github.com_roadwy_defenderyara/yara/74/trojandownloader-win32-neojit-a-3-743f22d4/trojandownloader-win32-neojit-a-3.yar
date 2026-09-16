rule TrojanDownloader_Win32_Neojit_A_3{
	meta:
		description = "TrojanDownloader:Win32/Neojit.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c6 25 01 00 00 80 79 05 48 83 c8 fe 40 85 c0 0f 85 ?? ?? 00 00 e9 90 16 0f b6 86 ?? ?? ?? ?? 0f b6 0a 2a c8 f6 d1 32 c8 88 0a e9 ?? ?? 00 00 00 00 00 00 } 		$a_03_1 = {6a 73 ff d0 e9 ?? ?? ?? ?? 00 00 00 00 90 09 0a 00 68 ?? ?? ?? ?? 68 } 		$a_03_2 = {6a 73 ff d0 eb ?? 00 00 00 00 90 09 0a 00 68 ?? ?? ?? ?? 68 } 		$a_03_3 = {8b 45 fc c6 00 68 (e9 90 16|eb 90 14) 8b 45 fc 40 89 18 (e9 90 16|eb 90 14) 8b 45 fc 83 c0 05 c6 00 c3 (e9 90 16|eb 90 14) ff 55 fc } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}