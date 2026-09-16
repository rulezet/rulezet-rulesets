rule TrojanDownloader_Win32_Cutwail_BE_3{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BE,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_03_0 = {50 6a 18 ff 35 ?? ?? ?? ?? 90 17 03 01 06 02 e8 b8 ?? ?? ?? ?? ff d0 ff d7 } 		$a_03_1 = {81 c6 ca 01 00 00 (90 09 11 00|90 09 0e 00) b9 90 17 03 02 02 02 00 24 e2 25 ca 29 00 00 8b } 		$a_03_2 = {81 c6 ca 01 00 00 90 09 0e 00 b9 00 ?? ?? ?? c1 e9 02 } 		$a_03_3 = {ac 32 c3 aa f7 c1 01 00 00 00 74 ?? 85 c0 60 } 		$a_01_4 = {ad 33 85 f4 fc ff ff ab e2 db b8 00 } 		$a_03_5 = {ff ff ad 33 85 ?? ?? ff ff ab e2 90 09 0a 00 05 ?? ?? ?? ?? 50 8f 85 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=12
 
}