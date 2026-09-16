rule TrojanDownloader_Win32_Delf_NK_2{
	meta:
		description = "TrojanDownloader:Win32/Delf.NK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 00 69 00 79 00 61 00 79 00 75 00 6d 00 6e 00 65 00 } 		$a_01_1 = {2e 00 64 00 6f 00 77 00 6e 00 78 00 69 00 61 00 2e 00 6e 00 65 00 74 00 } 		$a_03_2 = {8b 14 98 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 7f 16 a1 ?? ?? ?? ?? 8b 14 98 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 7e 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}