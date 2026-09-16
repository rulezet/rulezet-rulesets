rule TrojanDownloader_Win32_Kuluoz_B{
	meta:
		description = "TrojanDownloader:Win32/Kuluoz.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a } 		$a_01_1 = {2f 69 6e 64 65 78 2e 70 68 70 3f 72 3d 67 61 74 65 26 69 64 3d } 		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } 		$a_01_3 = {26 67 72 6f 75 70 3d 00 26 64 65 62 75 67 3d 00 } 		$a_01_4 = {00 69 64 6c 00 72 75 6e 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}