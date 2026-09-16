rule TrojanDownloader_Win32_Agent_4{
	meta:
		description = "TrojanDownloader:Win32/Agent,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {84 12 14 00 28 12 14 00 68 74 74 70 3a 2f 2f 67 65 74 79 6f 75 6e 65 65 64 2e 63 6f 6d 2f 72 2e 70 68 70 3f 77 6d 3d 35 } 		$a_01_1 = {f0 fa 12 00 11 26 40 00 1c fa 12 00 60 fa 12 00 00 00 00 00 00 00 00 00 68 74 74 70 3a 2f 2f 67 65 74 79 6f 75 6e 65 65 64 2e 63 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}