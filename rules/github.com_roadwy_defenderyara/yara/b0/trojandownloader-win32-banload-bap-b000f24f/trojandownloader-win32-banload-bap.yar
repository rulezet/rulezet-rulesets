rule TrojanDownloader_Win32_Banload_BAP{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-10] 2e 63 70 6c 00 } 		$a_02_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-10] 2e 74 6d 70 00 [0-10] 68 74 74 70 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}