rule TrojanDownloader_Win32_Upatre_H{
	meta:
		description = "TrojanDownloader:Win32/Upatre.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 00 65 00 73 00 2f 00 68 00 74 00 6d 00 6c 00 2f 00 2a 00 78 00 65 00 } 		$a_01_1 = {68 00 74 00 62 00 6b 00 67 00 72 00 6e 00 64 00 } 		$a_01_2 = {8b 45 b4 ff e0 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}