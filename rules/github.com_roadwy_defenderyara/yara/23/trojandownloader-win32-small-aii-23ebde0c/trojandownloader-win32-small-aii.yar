rule TrojanDownloader_Win32_Small_AII{
	meta:
		description = "TrojanDownloader:Win32/Small.AII,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 10 8a 54 24 14 53 55 8b c1 2b f1 8b ef 8a 1c 06 32 da 88 18 40 4d 75 f5 5d c6 04 0f 00 } 		$a_01_1 = {4e 65 66 6b 68 65 55 3c 3e 38 48 4d 3d 3d 31 24 38 4f 3f 30 24 3d 3e 6d 3c 24 48 4c 4a 38 24 4d 3c 4c 48 3b 3b 3a 3d 3d 39 30 4b } 		$a_01_2 = {31 3d 3e 3c 27 3e 3e 39 3a 39 3d 38 3b 3a 27 6a 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}