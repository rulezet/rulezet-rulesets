rule TrojanDownloader_Win32_Vundo_J{
	meta:
		description = "TrojanDownloader:Win32/Vundo.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 fa 8b 74 05 80 fa 55 75 90 04 01 01 11 } 		$a_03_1 = {2b d9 0f b6 1b 0f b6 d2 2b d3 83 fa 12 74 90 04 01 01 3b } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}