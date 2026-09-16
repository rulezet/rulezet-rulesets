rule TrojanDownloader_Win32_Karagany_L_2{
	meta:
		description = "TrojanDownloader:Win32/Karagany.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 8d 8e ac 04 00 00 51 6a 02 50 ff d7 6a 04 8d 86 b4 04 00 00 50 6a 06 ff b6 08 04 00 00 ff d7 6a 04 } 		$a_03_1 = {89 48 08 c7 45 ?? b9 7b 59 42 c7 45 ?? 92 42 63 d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}