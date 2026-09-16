rule TrojanDownloader_Win32_Banload_BAS{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 32 30 30 37 } 		$a_01_1 = {70 77 3d 25 78 } 		$a_03_2 = {50 6a 00 6a 00 ff d3 8b d8 eb 0a 68 ?? ?? 00 00 e8 ?? ?? ?? ?? 84 db 74 f2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}