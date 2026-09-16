rule TrojanDownloader_Win32_Delf_LT{
	meta:
		description = "TrojanDownloader:Win32/Delf.LT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 65 6d 70 31 25 64 2e 74 78 74 } 		$a_01_1 = {7b 39 46 43 35 37 37 39 44 2d 33 42 35 38 2d 34 44 35 46 2d 42 41 32 41 2d 39 42 41 43 36 34 45 43 34 36 41 45 7d } 		$a_03_2 = {74 65 73 74 2e 35 32 63 6f 6d 6e 65 74 63 6e 2e 63 6f 6d ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 74 74 70 3a 2f 2f 25 73 2f 74 6f 6f 6c 73 2e 74 78 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}