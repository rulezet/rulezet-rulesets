rule TrojanDownloader_Win32_Banload_BGS_3{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 00 62 00 72 00 36 00 30 00 30 00 72 00 72 00 } 		$a_01_1 = {41 00 44 00 38 00 44 00 38 00 32 00 42 00 46 00 46 00 37 00 33 00 39 00 43 00 30 00 } 		$a_01_2 = {03 04 9e 03 84 9d f0 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 } 		$a_03_3 = {83 c4 88 53 33 d2 89 55 90 90 89 55 8c 89 55 88 89 55 fc 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 45 fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 32 8d 45 96 50 e8 ?? ?? ?? ?? 0f b7 c0 50 e8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}