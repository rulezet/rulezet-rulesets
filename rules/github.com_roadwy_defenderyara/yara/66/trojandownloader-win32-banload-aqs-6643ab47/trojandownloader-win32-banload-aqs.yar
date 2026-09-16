rule TrojanDownloader_Win32_Banload_AQS{
	meta:
		description = "TrojanDownloader:Win32/Banload.AQS,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 44 30 37 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 } 		$a_01_1 = {73 6d 00 00 ff ff ff ff 06 00 00 00 69 64 2e 73 79 73 00 00 ff ff ff ff 5c 00 00 00 44 38 37 35 39 31 38 36 39 36 44 46 31 32 32 46 33 38 41 36 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}