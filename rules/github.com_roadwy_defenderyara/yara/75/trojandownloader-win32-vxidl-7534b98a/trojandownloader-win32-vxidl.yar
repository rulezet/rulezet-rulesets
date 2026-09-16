rule TrojanDownloader_Win32_VXIDL{
	meta:
		description = "TrojanDownloader:Win32/VXIDL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 00 64 00 6f 00 67 00 2e 00 73 00 79 00 73 00 00 00 00 00 7a 00 63 00 6c 00 69 00 65 00 6e } 		$a_01_1 = {61 00 76 00 73 00 73 00 2e 00 65 00 78 00 65 00 00 00 6b 00 61 00 76 00 73 00 76 00 63 00 2e 00 } 		$a_00_2 = {0f 20 c0 50 25 ff ff fe ff 0f 22 c0 } 		$a_01_3 = {00 00 8b 55 10 66 81 3a 4d 5a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}