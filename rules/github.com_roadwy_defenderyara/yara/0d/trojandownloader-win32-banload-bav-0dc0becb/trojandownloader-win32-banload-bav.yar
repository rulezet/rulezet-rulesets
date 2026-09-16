rule TrojanDownloader_Win32_Banload_BAV{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 04 00 00 00 6a 63 8d 8d f0 fe ff ff 51 ff 15 ?? ?? ?? ?? 6a 6f 8d 95 e0 fe ff ff } 		$a_03_1 = {81 c4 d4 00 00 00 c7 45 fc 07 00 00 00 6a 4c 8d 85 f0 fe ff ff 50 ff 15 ?? ?? ?? ?? 6a 4f 8d 8d e0 fe ff ff } 		$a_03_2 = {6a 5c 8d 85 70 fd ff ff 50 ff 15 ?? ?? ?? ?? 6a 74 8d 8d 60 fd ff ff 51 ff 15 ?? ?? ?? ?? 6a 65 } 		$a_11_3 = {00 61 00 72 00 72 00 65 00 67 00 61 00 6e 00 64 00 6f 00 2e 00 2e 00 2e 00 00 00 01 } 		$a_64_4 = {75 00 6c 00 6f 00 20 00 65 00 73 00 70 00 65 00 63 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_11_3  & 1)*1+(#a_64_4  & 1)*9728) >=5
 
}