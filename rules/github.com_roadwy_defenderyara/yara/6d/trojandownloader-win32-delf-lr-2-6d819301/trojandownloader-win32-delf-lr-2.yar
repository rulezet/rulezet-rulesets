rule TrojanDownloader_Win32_Delf_LR_2{
	meta:
		description = "TrojanDownloader:Win32/Delf.LR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {d1 eb 0b cb 89 0a 8b 08 33 0a 81 e1 aa aa aa aa } 		$a_01_1 = {4d 79 20 44 72 6f 70 62 6f 78 5c 50 72 6f 6a 65 74 6f 73 5c 4a 61 76 61 6e 5c 73 74 61 72 74 5c 70 75 6d 61 6e 65 77 5f 32 5c 70 75 6d 61 78 2e 64 70 72 } 		$a_01_2 = {43 41 50 41 2d 43 45 4c 55 4c 41 52 00 00 00 00 55 8b ec } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}