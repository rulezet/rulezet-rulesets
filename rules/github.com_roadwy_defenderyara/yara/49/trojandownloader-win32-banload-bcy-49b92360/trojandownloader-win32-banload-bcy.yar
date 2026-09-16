rule TrojanDownloader_Win32_Banload_BCY{
	meta:
		description = "TrojanDownloader:Win32/Banload.BCY,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 db 8a 5c 30 ff 33 5d e8 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 2b df 8d 45 d4 8b d3 } 		$a_01_1 = {5c 7a 2e 7a 6c 69 62 } 		$a_01_2 = {5c 61 62 63 64 65 66 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}