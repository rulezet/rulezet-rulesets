rule TrojanDownloader_Win32_Banload_ADP{
	meta:
		description = "TrojanDownloader:Win32/Banload.ADP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 4d c8 0f bf d0 51 52 ff 15 a4 10 40 00 8b 35 e8 10 40 00 8b d0 8d 4d c0 ff d6 50 ff 15 2c 10 40 00 } 		$a_01_1 = {78 41 44 00 e2 00 e8 00 d5 00 7f 00 9d 00 a3 00 c9 00 b1 00 53 01 d8 00 d7 00 b4 00 de 00 d6 00 d4 00 } 		$a_01_2 = {42 00 75 00 67 00 2e 00 65 00 78 00 65 00 } 		$a_01_3 = {6a 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 } 		$a_01_4 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}