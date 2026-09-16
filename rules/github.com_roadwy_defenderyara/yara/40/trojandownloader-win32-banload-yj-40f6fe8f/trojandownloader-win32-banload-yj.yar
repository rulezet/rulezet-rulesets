rule TrojanDownloader_Win32_Banload_YJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.YJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 3e 03 7c b5 80 3b 00 74 1f 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 05 ?? ?? ?? ?? ff 4d fc 0f 85 } 		$a_01_1 = {5a 3a 5c 50 72 6f 6a 65 74 6f 73 5c 6e 65 77 68 6f 70 65 5c 63 66 67 5c 76 64 62 5c 6c 69 62 5c 56 44 42 5f } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}