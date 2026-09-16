rule TrojanDownloader_Win32_Swizzor_AB{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.AB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 73 65 72 76 69 63 65 31 2e 69 6e 69 } 		$a_01_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 4b 42 39 37 38 39 37 38 2e 6c 6f 67 } 		$a_01_2 = {65 3a 5c 4a 69 6e 5a 51 5c } 		$a_01_3 = {70 72 6f 63 65 73 73 31 00 70 72 6f 63 65 73 73 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}