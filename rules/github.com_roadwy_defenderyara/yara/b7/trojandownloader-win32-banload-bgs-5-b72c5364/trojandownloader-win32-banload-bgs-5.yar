rule TrojanDownloader_Win32_Banload_BGS_5{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 da 07 00 00 33 c9 8b 15 ?? ?? ?? 00 8b 45 90 0a b0 00 ff 75 f0 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 90 1b 02 00 68 ?? ?? ?? ?? b8 ?? ?? ?? ?? ba 05 00 00 00 } 		$a_01_1 = {4c 69 73 74 5f 46 69 6c 65 73 5f 47 65 74 41 70 70 64 61 74 61 46 6f 6c 64 65 72 } 		$a_01_2 = {03 04 9e 03 84 9d f0 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 } 		$a_03_3 = {83 c4 88 53 33 d2 89 55 90 90 89 55 8c 89 55 88 89 55 fc 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 45 fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 32 8d 45 96 50 e8 ?? ?? ?? ?? 0f b7 c0 50 e8 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}