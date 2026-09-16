rule TrojanDownloader_Win32_Banker_J_2{
	meta:
		description = "TrojanDownloader:Win32/Banker.J,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 74 6f 74 61 6c 76 69 73 69 74 61 2e 6a 70 67 00 } 		$a_01_1 = {2e 63 6f 6d 2f 70 63 2e 74 78 74 00 } 		$a_01_2 = {2f 63 6f 6e 74 61 64 6f 72 65 2f 65 6e 74 72 61 72 2e 70 68 70 00 } 		$a_01_3 = {32 30 38 2e 31 31 35 2e 32 33 38 2e 31 30 39 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}