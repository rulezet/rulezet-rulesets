rule TrojanDownloader_Win32_Zlob_ANS{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANS,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {5f 5f 54 48 5f 53 54 4f 50 5f 5f 00 } 		$a_01_1 = {5f 5f 50 4d 5f 4d 4f 4e 49 54 4f 52 5f 53 54 4f 50 5f 5f 00 } 		$a_01_2 = {5f 5f 48 49 52 45 5f 5f 00 } 		$a_01_3 = {4c 00 4f 00 48 00 49 00 00 00 } 		$a_01_4 = {53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 } 		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } 		$a_01_6 = {25 73 61 73 77 65 25 64 2e 65 78 25 73 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*3) >=7
 
}