rule TrojanDownloader_WinNT_Banload_Q{
	meta:
		description = "TrojanDownloader:WinNT/Banload.Q,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3f 64 69 72 65 63 74 44 6f 77 6e 6c 6f 61 64 3d 74 72 75 65 } 		$a_01_1 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 73 75 67 61 72 73 79 6e 63 2e 63 6f 6d 2f 70 66 } 		$a_01_2 = {21 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 52 75 6e 64 6c 6c 33 32 2e 65 78 65 } 		$a_01_3 = {42 61 6e 67 2e 6a 61 76 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}