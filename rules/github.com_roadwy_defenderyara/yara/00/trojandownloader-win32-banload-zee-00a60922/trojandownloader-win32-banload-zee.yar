rule TrojanDownloader_Win32_Banload_ZEE{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEE,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00 } 		$a_01_1 = {61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f } 		$a_01_2 = {63 65 72 74 69 66 69 63 6f 2e 63 6f 6d 2e 62 72 2f } 		$a_01_3 = {54 6d 61 69 6e 30 31 39 32 39 30 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1) >=31
 
}