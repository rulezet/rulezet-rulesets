rule TrojanDownloader_Win32_Chasendi_A_2{
	meta:
		description = "TrojanDownloader:Win32/Chasendi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {23 7d d0 89 c8 c1 e8 03 32 1c 3a ba 19 86 61 18 f7 e2 d1 ea 69 c2 a8 00 00 00 f7 d8 02 9c 01 ?? ?? ?? ?? 88 1e 46 3b 75 d8 0f 82 b6 ff ff ff } 		$a_03_1 = {0f 85 14 ff ff ff 8b 55 d4 8d 4a 01 8d 04 c9 89 cf 8d 04 40 8b 84 02 ?? ?? ?? ?? 85 c0 0f 85 77 fe ff ff } 		$a_01_2 = {88 1e 46 3b 75 d8 0f 82 c4 ff ff ff e9 69 00 00 00 } 		$a_03_3 = {8d 3c 39 8b 5d cc 23 7d d8 2a 14 3b 89 f3 8b 7d d4 29 cb 0f b6 ca 0f b7 8c 09 ?? ?? ?? ?? 01 cb 88 18 40 89 f3 39 f8 0f } 		$a_03_4 = {0f b6 08 89 da 29 c2 0f b7 8c 09 ?? ?? ?? ?? 01 ca 88 10 40 39 f8 0f 82 e4 ff ff ff e9 62 00 00 00 } 		$a_03_5 = {3d 87 1c 00 00 89 45 e4 0f 85 2b ff ff ff 8b 55 e0 8d 4a 01 8d 04 c9 89 cf 8d 04 40 8b 84 02 ?? ?? ?? ?? 85 c0 0f 85 be fe ff ff } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}