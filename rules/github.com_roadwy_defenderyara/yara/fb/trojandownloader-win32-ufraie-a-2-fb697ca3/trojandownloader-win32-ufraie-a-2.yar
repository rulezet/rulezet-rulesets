rule TrojanDownloader_Win32_Ufraie_A_2{
	meta:
		description = "TrojanDownloader:Win32/Ufraie.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 4a 57 72 6f 6b 5c 6a 72 6e 41 6f 78 5c 67 74 45 59 2e 70 64 62 } 		$a_01_1 = {4c 3a 5c 59 67 62 59 68 6f 76 6d 5c 61 77 78 5a 43 63 63 5c 6c 6c 64 62 73 66 2e 70 64 62 } 		$a_01_2 = {54 3a 5c 79 4d 65 41 6c 42 79 72 5c 73 71 57 64 42 5c 41 7a 64 7a 66 5c 7a 70 57 44 2e 70 64 62 } 		$a_01_3 = {59 3a 5c 71 64 67 63 42 62 6d 79 5c 6b 6a 6c 57 76 61 4e 5c 4f 53 78 66 62 76 74 5c 79 6e 61 66 6c 5c 76 69 66 49 72 7a 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}