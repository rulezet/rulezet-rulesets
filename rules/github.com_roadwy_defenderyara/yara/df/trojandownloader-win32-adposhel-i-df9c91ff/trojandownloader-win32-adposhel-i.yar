rule TrojanDownloader_Win32_Adposhel_I{
	meta:
		description = "TrojanDownloader:Win32/Adposhel.I,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {65 63 68 6f 20 62 69 74 73 61 64 6d 69 6e 20 2f 63 6f 6d 70 6c 65 74 65 } 		$a_00_1 = {65 63 68 6f 20 62 69 74 73 61 64 6d 69 6e 20 2f 63 61 6e 63 65 6c } 		$a_00_2 = {65 63 68 6f 20 73 74 61 72 74 20 2f 62 20 2f 6d 69 6e 20 72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 20 2f 6e 20 2f 69 3a } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2) >=4
 
}