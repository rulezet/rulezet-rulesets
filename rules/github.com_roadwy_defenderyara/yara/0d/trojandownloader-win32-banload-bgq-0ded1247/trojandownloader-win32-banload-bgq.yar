rule TrojanDownloader_Win32_Banload_BGQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 6d 00 75 00 73 00 74 00 2e 00 70 00 69 00 67 00 } 		$a_03_1 = {64 00 65 00 6e 00 74 00 6f 00 6f 00 6c 00 73 00 [0-10] 2e 00 37 00 7a 00 69 00 70 00 } 		$a_01_2 = {59 00 44 00 44 00 40 00 0b 00 1f 00 1f } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}