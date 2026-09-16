rule TrojanDownloader_Win32_Banload_XP_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.XP,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 74 65 6d 70 2f 73 73 2e 63 6f 6d } 		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d } 		$a_01_2 = {58 50 50 52 4f 42 54 32 30 30 39 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}