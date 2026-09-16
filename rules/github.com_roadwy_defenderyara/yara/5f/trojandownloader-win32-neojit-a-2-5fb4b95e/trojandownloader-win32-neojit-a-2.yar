rule TrojanDownloader_Win32_Neojit_A_2{
	meta:
		description = "TrojanDownloader:Win32/Neojit.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 6e 65 77 67 2f 61 2e 70 68 70 00 } 		$a_01_1 = {00 41 63 63 65 73 73 69 6e 67 20 74 68 65 20 73 65 72 76 65 72 2e 2e 2e 00 } 		$a_01_2 = {00 55 70 64 61 74 65 20 61 70 70 20 2d 3e 20 00 } 		$a_01_3 = {00 44 6f 77 6e 6c 6f 61 64 20 75 72 6c 20 3d 20 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}