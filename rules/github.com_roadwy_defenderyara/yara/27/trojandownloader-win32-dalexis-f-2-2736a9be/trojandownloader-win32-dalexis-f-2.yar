rule TrojanDownloader_Win32_Dalexis_F_2{
	meta:
		description = "TrojanDownloader:Win32/Dalexis.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b 6c 69 70 6f 70 67 61 2e 70 64 62 } 		$a_01_1 = {42 68 58 59 4a 6d 6c 65 6e 78 48 66 78 } 		$a_01_2 = {b9 c6 78 3e 17 81 e9 f6 71 3e 17 51 b8 c6 78 3e 17 2d f6 71 3e 17 50 be f6 71 42 17 81 ee f6 71 3e 17 } 		$a_01_3 = {f8 83 d0 04 83 c3 f7 f7 d3 29 fb 43 29 ff 4f 21 df c1 c7 03 c1 c7 05 89 1e f8 83 d6 04 8d 52 fc } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}