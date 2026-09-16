rule TrojanDownloader_Win32_Clikug_A{
	meta:
		description = "TrojanDownloader:Win32/Clikug.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {7a 00 67 00 69 00 67 00 61 00 63 00 6c 00 69 00 63 00 6b 00 73 00 00 00 } 		$a_01_1 = {2e 3f 41 56 43 47 69 67 61 43 6c 69 63 6b 73 49 6e 66 6f 40 40 } 		$a_01_2 = {2e 3f 41 56 43 54 69 6e 79 49 6e 73 74 61 6c 6c 65 72 41 70 70 40 40 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}