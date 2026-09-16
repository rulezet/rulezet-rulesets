rule TrojanDownloader_Win32_Renos_JH{
	meta:
		description = "TrojanDownloader:Win32/Renos.JH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 1a 5b f7 f3 8b 5d 08 8a 44 15 ce 8b 55 f8 88 04 1a 8d 57 ff 3b f2 7d 05 } 		$a_01_1 = {8b 30 0f af 37 46 89 30 8b 09 8b 74 24 0c 8b 06 0f b7 4c 8a 02 } 		$a_01_2 = {c7 00 35 4e 5a 01 83 23 00 } 		$a_01_3 = {61 20 22 2e 2e 5c 25 73 2e 72 61 72 22 20 2a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=3
 
}