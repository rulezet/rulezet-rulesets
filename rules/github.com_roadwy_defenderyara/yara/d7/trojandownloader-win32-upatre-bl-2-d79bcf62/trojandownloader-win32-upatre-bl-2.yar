rule TrojanDownloader_Win32_Upatre_BL_2{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BL,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 10 00 00 68 f8 ff a7 00 6a 00 ff 55 40 } 		$a_01_1 = {05 80 84 1e 00 89 45 b8 05 80 8d 5b 00 89 45 f4 5a 03 c2 } 		$a_01_2 = {b8 52 00 45 00 40 ab b0 52 66 ab } 		$a_01_3 = {b8 54 00 45 00 48 ab b0 52 66 ab } 		$a_01_4 = {b0 2e 48 66 ab b0 53 6a 50 66 ab 58 66 ab 58 48 66 ab } 		$a_01_5 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 } 		$a_01_6 = {00 74 65 78 74 2f 2a 00 } 		$a_01_7 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}