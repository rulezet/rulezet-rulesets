rule TrojanDownloader_Win32_Banload_AKY_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.AKY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f [0-20] 2e 6a 70 67 } 		$a_03_1 = {68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f [0-20] 2e 73 77 66 } 		$a_01_2 = {6d 66 72 73 30 39 35 2e 65 78 65 } 		$a_01_3 = {54 61 73 6b 62 61 72 43 72 65 61 74 65 64 } 		$a_01_4 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}