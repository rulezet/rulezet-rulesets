rule TrojanDownloader_Win32_Delf_2{
	meta:
		description = "TrojanDownloader:Win32/Delf,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {ba cc 03 45 00 e8 ?? ?? ?? ff b8 20 ea 45 00 ba 00 04 45 00 } 		$a_03_1 = {ba 18 04 45 00 e8 ?? ?? ?? ff b8 20 ea 45 00 ba 54 04 45 00 } 		$a_00_2 = {76 69 64 73 78 78 78 76 69 64 73 2e 63 6f 6d } 		$a_00_3 = {73 65 6c 6c 62 75 79 74 72 61 66 66 2e 63 6f 6d } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}