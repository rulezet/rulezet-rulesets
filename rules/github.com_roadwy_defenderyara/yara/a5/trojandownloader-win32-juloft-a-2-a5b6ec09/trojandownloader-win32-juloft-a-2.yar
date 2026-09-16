rule TrojanDownloader_Win32_Juloft_A_2{
	meta:
		description = "TrojanDownloader:Win32/Juloft.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 2e 63 6e 2f 64 61 74 61 2f 64 61 74 61 2e 68 74 6d 6c } 		$a_01_1 = {6a 75 6c 79 73 6f 66 74 2e 65 78 65 } 		$a_01_2 = {6a 61 76 61 73 63 72 69 70 74 3a } 		$a_01_3 = {61 62 6f 75 74 2e 69 6e 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}