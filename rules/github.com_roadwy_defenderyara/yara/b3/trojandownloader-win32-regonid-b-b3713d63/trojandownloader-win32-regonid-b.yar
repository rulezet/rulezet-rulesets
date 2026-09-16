rule TrojanDownloader_Win32_Regonid_B{
	meta:
		description = "TrojanDownloader:Win32/Regonid.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 29 8b d0 2b d1 03 55 14 83 fa 7e 76 03 83 c1 7e 8b 55 08 8a 14 10 2a 55 14 } 		$a_01_1 = {3c 41 72 5f 3c 47 73 04 2c 37 eb f0 3c 61 72 53 3c 67 73 04 2c 57 eb e4 } 		$a_01_2 = {f7 da 1b d2 81 e2 b7 1d c1 04 03 c0 33 c2 49 75 e7 50 b1 20 89 06 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}