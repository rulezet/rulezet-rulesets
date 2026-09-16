rule TrojanDownloader_Win32_Banload_AAH{
	meta:
		description = "TrojanDownloader:Win32/Banload.AAH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {63 6d 64 20 2f 6b 20 63 3a 5c 50 72 6f 6a 65 63 74 90 05 02 03 30 2d 39 2e 67 69 66 } 		$a_03_1 = {2e 73 69 74 65 (62 72|62 72 61 73 69 6c) 2e 90 03 03 03 6e 65 74 6f 72 67 2f [0-15] 2e 67 69 66 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}