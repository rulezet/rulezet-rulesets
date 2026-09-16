rule TrojanDownloader_Win32_Juloft_A_3{
	meta:
		description = "TrojanDownloader:Win32/Juloft.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 2e 63 6e 2f 64 61 74 61 2f 61 62 6f 75 74 2e 68 74 6d 6c 3f } 		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 31 2e 63 6e 2f 64 61 74 61 2f 74 6a 2f 63 6f 75 6e 74 2e 70 68 70 3f 4d 41 43 3d } 		$a_01_2 = {64 6c 6c 63 61 63 68 65 5c 63 69 73 76 63 2e 65 78 65 } 		$a_01_3 = {73 63 20 63 6f 6e 66 69 67 20 43 69 53 76 63 20 73 74 61 72 74 3d 20 61 75 74 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}