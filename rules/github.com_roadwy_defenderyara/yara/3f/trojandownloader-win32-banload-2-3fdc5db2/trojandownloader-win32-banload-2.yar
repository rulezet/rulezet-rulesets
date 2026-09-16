rule TrojanDownloader_Win32_Banload_2{
	meta:
		description = "TrojanDownloader:Win32/Banload,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {43 40 ff 28 30 ff 01 00 fc f6 68 ff f4 1e 70 50 ff f3 ff 00 70 52 ff 28 10 ff 01 00 04 58 ff 80 0c 00 4a fd 69 20 ff fe 68 f0 fe 77 01 0a ?? 00 00 00 04 68 ff 28 30 ff 01 00 fb } 		$a_01_1 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 53 00 74 00 72 00 69 00 6e 00 67 00 00 00 } 		$a_01_2 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 00 00 } 		$a_01_3 = {53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00 00 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}