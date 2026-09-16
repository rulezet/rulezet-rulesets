rule TrojanDownloader_Win32_Renos_CO{
	meta:
		description = "TrojanDownloader:Win32/Renos.CO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 41 6a 02 6a fc ff 75 fc ff 15 ?? ?? ?? 10 83 c4 0c ff 75 fc 6a 01 6a 04 8d 45 f8 50 ff 15 ?? ?? ?? 10 83 c4 10 e8 ?? ?? ff ff 3b 45 f8 75 07 c7 45 f4 01 00 00 00 } 		$a_03_1 = {68 02 00 00 80 e8 ?? ?? 00 00 03 45 0c 83 c0 02 83 e8 02 80 3e 00 90 90 90 90 74 08 90 90 90 90 90 90 30 06 46 eb f1 68 } 		$a_01_2 = {61 61 62 00 61 61 6c 00 61 6c 6c 65 72 74 32 00 66 67 6c 6c 65 72 74 00 71 6f 61 64 00 77 69 6e 64 6f 77 73 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}