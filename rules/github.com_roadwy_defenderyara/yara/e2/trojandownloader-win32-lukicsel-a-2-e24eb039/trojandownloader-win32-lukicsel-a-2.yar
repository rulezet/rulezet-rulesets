rule TrojanDownloader_Win32_Lukicsel_A_2{
	meta:
		description = "TrojanDownloader:Win32/Lukicsel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {42 48 75 f1 e8 90 09 05 00 80 74 11 ff } 		$a_03_1 = {8a 54 3a ff 80 f2 ?? e8 ?? ?? ?? ?? 8b 55 f8 8b c6 } 		$a_01_2 = {66 b9 50 00 8b 55 fc } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}