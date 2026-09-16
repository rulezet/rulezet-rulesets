rule TrojanDownloader_Win32_Adload_DX_bit{
	meta:
		description = "TrojanDownloader:Win32/Adload.DX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2d 77 65 73 74 2d 32 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f [0-50] 2f 4a 61 77 5a 69 67 61 2e 65 78 65 } 		$a_01_1 = {7b 74 6d 70 7d 5c 4a 61 77 5a 69 67 61 2e 65 78 65 } 		$a_01_2 = {00 2e 63 6f 6e 66 69 67 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}