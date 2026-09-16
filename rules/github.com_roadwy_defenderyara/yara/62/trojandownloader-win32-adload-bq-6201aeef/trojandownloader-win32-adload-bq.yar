rule TrojanDownloader_Win32_Adload_BQ{
	meta:
		description = "TrojanDownloader:Win32/Adload.BQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 50 fe 4c fe 48 fe 44 fe 40 fe 3c fe 38 fe 34 fe 30 fe 2c fe 28 fe 24 fe 20 fe 1c fe } 		$a_03_1 = {04 1a fd 04 58 ff 3a 44 ff ?? 00 04 b4 fd fb ef 34 ff 04 d4 fd fb ef 14 ff 60 fd c7 50 fe 10 f8 06 ?? 00 6b 1a fd 2f 50 fe 36 04 00 34 ff 14 ff 1c 27 05 00 27 f5 03 00 00 00 6c 58 ff 1b ?? 00 2a 46 34 ff 04 6c ff fb ef 14 ff 0a ?? 00 08 00 74 10 fd 36 04 00 34 ff 14 ff } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}