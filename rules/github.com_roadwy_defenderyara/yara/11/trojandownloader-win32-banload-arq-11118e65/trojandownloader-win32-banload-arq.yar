rule TrojanDownloader_Win32_Banload_ARQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ARQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 5c 52 75 6e 20 2f 66 20 2f 76 20 65 76 78 20 2f 64 20 22 72 65 67 73 76 72 33 32 } 		$a_03_1 = {5c 65 76 78 2e 72 33 78 00 72 [0-06] 90 04 06 07 68 74 70 5b 5d 3a 2f } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}