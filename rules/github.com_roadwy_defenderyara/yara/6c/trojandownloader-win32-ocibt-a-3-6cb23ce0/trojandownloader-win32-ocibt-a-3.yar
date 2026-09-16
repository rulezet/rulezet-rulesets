rule TrojanDownloader_Win32_Ocibt_A_3{
	meta:
		description = "TrojanDownloader:Win32/Ocibt.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 50 4f 50 55 50 } 		$a_02_1 = {68 74 74 70 3a 2f 2f 6d 6d 35 38 2e 66 72 65 65 6e 76 2e 69 6e 66 6f 3a 37 37 37 2f [0-20] 2e 70 68 70 3f 6d 61 63 3d } 		$a_00_2 = {68 74 74 70 3a 2f 2f 67 6f 2e 69 75 79 74 2e 69 6e 66 6f 2f 64 6f 77 6e 2e 70 68 70 3f 69 3d 61 26 } 		$a_00_3 = {68 74 74 70 3a 2f 2f 67 6f 2e 69 75 79 74 2e 69 6e 66 6f 2f 64 6f 77 6e 2e 70 68 70 3f 69 3d 74 61 6b 65 26 } 		$a_00_4 = {5c 61 61 31 5f fd 83 80 fd 84 80 fd 85 80 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}