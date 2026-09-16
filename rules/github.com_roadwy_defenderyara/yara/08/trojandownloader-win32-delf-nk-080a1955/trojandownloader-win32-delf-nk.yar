rule TrojanDownloader_Win32_Delf_NK{
	meta:
		description = "TrojanDownloader:Win32/Delf.NK,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {36 30 2e 31 39 31 2e 32 35 34 2e 32 35 33 } 		$a_01_1 = {73 74 64 33 33 32 32 2e 63 6f 6d } 		$a_01_2 = {67 6c 61 64 31 32 33 2e 63 6f 6d } 		$a_01_3 = {63 6c 75 64 33 33 2e 63 6f 6d } 		$a_01_4 = {5c 73 65 74 6f 70 33 30 31 30 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10) >=10
 
}