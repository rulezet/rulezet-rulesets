rule TrojanDownloader_Win32_Agent_3{
	meta:
		description = "TrojanDownloader:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,ffffff82 00 ffffff82 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 75 72 6c 6d 31 30 6e 2e 64 6c 6c } 		$a_01_1 = {5c 75 72 6c 6d 6f 6e 2e 64 6c 6c } 		$a_01_2 = {5c 69 6e 64 65 78 31 2e 64 61 74 } 		$a_01_3 = {5c 49 6e 66 6f 31 2e 69 6e 69 } 		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 32 38 32 38 68 66 64 79 2e 63 6f 6d 2f 62 61 6b 2e 74 78 74 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*100) >=130
 
}