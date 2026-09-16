rule TrojanDownloader_Win32_Banload_QI{
	meta:
		description = "TrojanDownloader:Win32/Banload.QI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b d8 66 83 eb 02 66 83 fb 03 76 40 8d 45 f0 50 0f b7 d3 b9 03 00 00 00 8b 45 fc e8 } 		$a_00_1 = {6d 6f 64 75 6c 6f 2e 74 78 74 } 		$a_00_2 = {6d 73 68 6f 74 2e 74 78 74 } 		$a_00_3 = {68 74 70 2e 74 78 74 } 	condition:
		((#a_01_0  & 1)*4+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}