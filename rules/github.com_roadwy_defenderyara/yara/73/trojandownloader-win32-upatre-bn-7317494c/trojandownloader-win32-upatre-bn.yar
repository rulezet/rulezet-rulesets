rule TrojanDownloader_Win32_Upatre_BN{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b0 54 6a 50 48 66 ab 58 66 ab 58 48 66 ab } 		$a_00_1 = {b0 2f aa 33 c0 aa b8 c8 00 00 00 } 		$a_00_2 = {6a 04 68 00 10 00 00 68 e4 dc a7 00 6a 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}