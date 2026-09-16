rule TrojanDownloader_Win32_Banload_OV{
	meta:
		description = "TrojanDownloader:Win32/Banload.OV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 4a 08 33 c9 89 4a 0c 8d 7a 14 be ?? ?? ?? ?? b9 08 00 00 00 f3 a5 8d 7a 34 be ?? ?? ?? ?? b9 10 00 00 00 f3 a5 8d 7a 74 be ?? ?? ?? ?? b9 20 00 00 00 f3 a5 eb ?? 33 c0 eb } 		$a_01_1 = {66 6c 61 73 68 62 61 63 6b 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}