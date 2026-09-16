rule TrojanDownloader_Win32_Renos_10{
	meta:
		description = "TrojanDownloader:Win32/Renos,SIGNATURE_TYPE_PEHSTR,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {32 32 43 2d 34 32 42 44 2d 41 38 43 42 2d 37 } 		$a_01_1 = {77 73 70 64 6c 2e 63 6f 6d } 		$a_01_2 = {78 74 77 61 50 5c 4d 69 63 } 		$a_01_3 = {5e 5e 65 73 2e 2b 2f 70 61 79 2f 25 73 } 		$a_01_4 = {3f 74 79 70 65 3d 6d 61 69 6e 26 70 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}