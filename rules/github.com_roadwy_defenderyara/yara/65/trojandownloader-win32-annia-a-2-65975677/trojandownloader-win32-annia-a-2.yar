rule TrojanDownloader_Win32_Annia_A_2{
	meta:
		description = "TrojanDownloader:Win32/Annia.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 07 04 0d eb 6e 8a 07 3c 4d 7f 1c 0f be c0 50 e8 ?? ?? ?? ?? 59 85 c0 74 0e 0f be 07 50 e8 ?? ?? ?? ?? 59 85 c0 75 d8 8a 07 3c 6e } 		$a_03_1 = {75 67 67 63 3a 2f 2f [0-10] 2f 6e 69 2e 72 6b 72 } 		$a_01_2 = {76 6d 77 61 72 65 00 00 76 69 72 74 75 61 6c 00 71 65 6d 75 00 00 00 00 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } 		$a_01_3 = {4a 65 76 67 72 53 76 79 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}