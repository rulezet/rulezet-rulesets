rule TrojanDownloader_Win32_Somex_A{
	meta:
		description = "TrojanDownloader:Win32/Somex.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {25 73 5c 25 73 65 78 2e 64 6c 6c } 		$a_00_1 = {4d 61 6e 61 67 65 73 20 74 68 65 20 52 50 43 20 6e 61 6d 65 20 73 65 72 76 69 63 65 20 6c 6f 61 64 } 		$a_01_2 = {00 42 49 4e 00 53 65 72 76 69 63 65 44 6c 6c 00 } 		$a_00_3 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } 		$a_00_4 = {43 72 65 61 74 65 53 65 72 76 69 63 65 41 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}