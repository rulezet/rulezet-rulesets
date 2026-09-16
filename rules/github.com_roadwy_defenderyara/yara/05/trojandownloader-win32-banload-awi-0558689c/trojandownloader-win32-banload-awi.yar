rule TrojanDownloader_Win32_Banload_AWI{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 0f b6 44 30 ff 33 c3 89 45 e0 3b 7d e0 7c 0f 8b 45 e0 } 		$a_01_1 = {5c 63 6d 64 2e 65 78 65 20 2f 6b 20 72 65 67 73 76 72 33 32 2e 65 78 65 20 20 22 } 		$a_01_2 = {61 70 6c 69 63 61 74 69 76 6f 73 5c } 		$a_01_3 = {32 2e 6a 70 67 22 } 		$a_01_4 = {35 2e 63 70 6c } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}