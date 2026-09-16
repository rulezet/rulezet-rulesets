rule TrojanDownloader_Win32_Banload_BDT_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.BDT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 5c 64 61 74 61 2e 7a 69 70 00 90 09 04 00 1c 00 00 00 } 		$a_03_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 5c 6e 74 63 68 6b 33 32 2e 65 78 65 00 90 09 04 00 1f 00 00 00 } 		$a_01_2 = {00 6f 70 65 6e 00 00 00 00 ff ff ff ff 0b 00 00 00 45 72 72 6f 72 20 39 30 30 34 35 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}