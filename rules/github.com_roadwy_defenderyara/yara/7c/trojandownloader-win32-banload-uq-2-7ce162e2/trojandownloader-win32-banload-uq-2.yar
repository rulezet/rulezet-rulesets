rule TrojanDownloader_Win32_Banload_UQ_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.UQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 8b 80 18 03 00 00 8b 55 f8 8b 04 90 90 8b 08 8b 45 fc 8b 90 90 20 03 00 00 8d 45 e8 e8 ?? ?? ?? ?? 8b 45 e8 e8 ?? ?? ?? ?? 50 6a 00 e8 } 		$a_03_1 = {8b 0e 8b 1f 38 d9 75 ?? 4a 74 ?? 38 fd 75 ?? 4a 74 ?? 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75 } 		$a_01_2 = {5f 5e 5b 59 59 5d c3 00 ff ff ff ff 01 00 00 00 5c 00 00 00 ff ff ff ff 01 00 00 00 53 00 00 00 } 		$a_00_3 = {49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 4a 4b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 } 	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}