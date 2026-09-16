rule TrojanDownloader_Win32_Upatre_BL{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {b8 04 00 00 00 6a 04 68 00 10 00 00 68 00 00 aa 00 51 ff 93 28 11 00 00 } 		$a_01_1 = {b9 80 84 1e 00 89 45 00 03 c1 81 c1 e0 06 5a 00 89 45 fc 03 c1 } 		$a_01_2 = {b0 54 fe c8 66 ab b0 44 fe c0 66 ab b0 52 66 ab } 		$a_01_3 = {b0 54 48 66 ab b0 50 66 ab 58 04 30 66 ab } 		$a_01_4 = {ad ab 8b c2 66 ad 66 ab 8b c2 ac 66 ab 49 75 f0 } 		$a_01_5 = {b0 31 66 ab b0 2f 66 ab 8a c1 04 30 66 ab b0 2f 66 ab } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}