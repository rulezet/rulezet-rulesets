rule TrojanDownloader_WinNT_OpenStream_gen_A{
	meta:
		description = "TrojanDownloader:WinNT/OpenStream.gen!A,SIGNATURE_TYPE_JAVAHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {21 28 4c 63 6f 6d 2f 6d 73 2f 73 65 63 75 72 69 74 79 2f 50 65 72 6d 69 73 73 69 6f 6e 49 44 3b 29 56 } 		$a_01_1 = {28 29 4c 6a 61 76 61 2f 6e 65 74 2f 55 52 4c 43 6f 6e 6e 65 63 74 69 6f 6e 3b } 		$a_01_2 = {45 52 52 4f 52 5f 45 58 45 4c 4f 41 44 45 52 } 		$a_01_3 = {4d 61 74 72 69 78 2e 6a 61 76 61 } 		$a_01_4 = {63 6f 6d 2f 6d 73 2f 77 69 6e 33 32 2f 4b 65 72 6e 65 6c 33 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}