rule TrojanDownloader_Win32_Lukicsel_A{
	meta:
		description = "TrojanDownloader:Win32/Lukicsel.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 0c 8b 09 8b 75 08 8b 36 4e a0 ?? ?? ?? ?? 30 04 31 e2 fb } 		$a_01_1 = {83 c0 07 50 8b f0 b4 2f ac 3c 00 74 04 38 e0 75 f7 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}