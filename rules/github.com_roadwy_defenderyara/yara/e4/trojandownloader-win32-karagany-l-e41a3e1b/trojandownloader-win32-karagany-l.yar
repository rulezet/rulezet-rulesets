rule TrojanDownloader_Win32_Karagany_L{
	meta:
		description = "TrojanDownloader:Win32/Karagany.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3c 3e 2e 2d 61 62 63 64 65 66 67 76 77 69 6f 6e 6c 6d 6b 68 74 70 } 		$a_01_1 = {ff 45 f8 8b 4d f8 8a 09 84 c9 75 d3 83 65 f8 00 8b ce eb 13 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}