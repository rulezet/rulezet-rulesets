rule TrojanDownloader_Win32_Nymaim_G{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc d1 f8 8b 4d 08 0f be 04 01 0f b6 4d 0c 33 c1 8b 4d f8 88 01 } 		$a_03_1 = {83 c4 01 68 ?? ?? ?? ?? 58 83 ec fd 50 c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}