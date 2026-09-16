rule TrojanDownloader_Win32_Banload_ADG{
	meta:
		description = "TrojanDownloader:Win32/Banload.ADG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 2a 6e 23 66 40 31 23 } 		$a_01_1 = {77 69 6e 78 2a 74 23 33 2a 32 2a 5c 2a 23 70 40 6a 63 23 74 40 61 2a 2e 6a 23 70 23 67 40 } 		$a_01_2 = {52 23 75 23 6e 2a 44 23 4c 23 4c 40 33 23 32 2e 40 65 78 65 40 } 		$a_01_3 = {63 68 23 61 2a 76 2a 65 2a 3d 2a 78 2a 63 2a 68 23 61 23 76 65 2a 26 23 75 23 72 2a 6c 23 3d 23 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}