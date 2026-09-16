rule TrojanDownloader_Win32_Delf_3{
	meta:
		description = "TrojanDownloader:Win32/Delf,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 8b d8 b8 a4 35 45 00 e8 5b 53 fb ff 84 c0 74 0e a1 c0 4e 45 00 8b 00 e8 e7 c7 ff ff 5b c3 } 		$a_00_1 = {77 69 6e 75 70 2e 6a 70 67 } 		$a_00_2 = {4f 75 74 6c 6f 6f 6b 73 2e 6a 70 67 } 		$a_02_3 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 4d 53 4e 20 4d 65 73 73 65 6e 67 65 72 5c 44 65 76 69 63 65 20 4d 61 6e 61 67 65 72 5c 6d 73 6e 67 72 5c [0-08] 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}