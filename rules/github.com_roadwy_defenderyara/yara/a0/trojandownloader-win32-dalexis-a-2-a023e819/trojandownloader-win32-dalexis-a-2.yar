rule TrojanDownloader_Win32_Dalexis_A_2{
	meta:
		description = "TrojanDownloader:Win32/Dalexis.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 00 47 00 45 00 54 00 00 00 25 00 73 00 75 00 70 00 64 00 61 00 74 00 65 00 5f 00 25 00 64 00 2e 00 } 		$a_01_1 = {25 00 73 00 74 00 65 00 6d 00 70 00 5f 00 63 00 61 00 62 00 5f 00 25 00 64 00 2e 00 63 00 61 00 62 00 00 00 } 		$a_01_2 = {83 c4 14 57 68 80 00 00 00 6a 02 57 6a 01 68 00 00 00 40 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}