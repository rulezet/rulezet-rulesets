rule TrojanDownloader_Win32_Zlob_12{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 7a 31 2e 6e 66 2d 32 2e 6e 65 74 2f 35 31 32 2e 74 78 74 } 		$a_01_1 = {25 73 5c 54 65 6d 70 5c 65 64 69 74 2e 6a 70 67 } 		$a_01_2 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 64 6c 6c 63 61 63 68 65 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}