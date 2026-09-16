rule TrojanDownloader_Win32_Banload_AKY{
	meta:
		description = "TrojanDownloader:Win32/Banload.AKY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ba 70 6a 45 00 e8 5d de fa ff a1 ?? 9a 45 00 b9 ?? 6a 45 00 8b 55 fc } 		$a_01_1 = {2e 6a 70 67 } 		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}