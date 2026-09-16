rule TrojanDownloader_Win32_Upatre_G{
	meta:
		description = "TrojanDownloader:Win32/Upatre.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e } 		$a_01_1 = {8b 4e 24 03 c8 03 c8 8b 45 fc 03 c8 0f b7 01 8b 4e 1c 8d 04 81 8b 4d fc 8b 04 01 } 		$a_01_2 = {8b 4d d4 8b 7d e4 8b 45 e8 03 f8 8b 75 f4 fc f3 a4 5e 6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 ff 75 f0 ff 55 58 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}