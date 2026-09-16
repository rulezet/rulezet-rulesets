rule TrojanDownloader_Win32_Ocibt_A_2{
	meta:
		description = "TrojanDownloader:Win32/Ocibt.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 50 4f 50 55 50 } 		$a_00_1 = {68 74 74 70 3a 2f 2f 67 6f 2e 69 75 79 74 2e 69 6e 66 6f 2f 64 6f 77 6e 2e 70 68 70 3f 69 3d 74 62 69 63 6f 26 } 		$a_00_2 = {68 74 74 70 3a 2f 67 6f 2e 69 75 79 74 2e 69 6e 66 6f 2f 64 6f 77 6e 2e 70 68 70 3f 69 3d 61 76 62 73 26 } 		$a_00_3 = {5c 77 69 6e 72 61 72 5c 69 63 6f 5c 74 61 6f 62 61 6f 2e 74 62 69 63 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}