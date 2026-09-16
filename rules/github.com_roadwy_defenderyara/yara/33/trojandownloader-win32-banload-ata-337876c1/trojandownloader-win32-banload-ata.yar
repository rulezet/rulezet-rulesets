rule TrojanDownloader_Win32_Banload_ATA{
	meta:
		description = "TrojanDownloader:Win32/Banload.ATA,SIGNATURE_TYPE_PEHSTR_EXT,66 00 66 00 03 00 00 "
		
	strings :
		$a_02_0 = {00 50 72 6f 6a 65 63 74 ?? 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 } 		$a_00_1 = {5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 46 6c 61 73 68 50 6c 61 79 65 72 2e 65 78 65 00 } 		$a_00_2 = {2e 63 6f 6d 2e 62 72 2f 46 6c 61 73 68 50 6c 61 79 65 72 2f 46 6c 61 73 68 50 6c 61 79 65 72 2e 65 78 65 00 } 	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=102
 
}