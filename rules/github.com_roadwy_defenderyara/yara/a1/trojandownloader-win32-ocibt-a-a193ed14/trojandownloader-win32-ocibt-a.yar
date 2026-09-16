rule TrojanDownloader_Win32_Ocibt_A{
	meta:
		description = "TrojanDownloader:Win32/Ocibt.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 50 4f 50 55 50 } 		$a_00_1 = {5c 73 79 73 74 65 6d 33 32 5c 77 69 6e 37 7a 69 70 2e 64 6c 6c } 		$a_00_2 = {68 74 74 70 3a 2f 2f 67 6f 2e 6d 79 7a 79 2e 69 6e 66 6f 2f 64 6f 77 6e 2e 70 68 70 3f 69 3d 62 64 6c 6c 26 } 		$a_00_3 = {68 74 74 70 3a 2f 2f 67 6f 2e 6d 79 7a 79 2e 69 6e 66 6f 2f 64 6f 77 6e 2e 70 68 70 3f 69 3d 62 65 78 65 26 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}