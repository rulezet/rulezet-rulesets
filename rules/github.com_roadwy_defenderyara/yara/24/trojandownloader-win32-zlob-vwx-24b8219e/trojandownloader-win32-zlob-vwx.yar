rule TrojanDownloader_Win32_Zlob_VWX{
	meta:
		description = "TrojanDownloader:Win32/Zlob.VWX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 85 fc fe ff ff 47 c6 85 fd fe ff ff 45 c6 85 fe fe ff ff 54 } 		$a_01_1 = {83 7c 24 08 30 7c 0c 83 7c 24 08 39 7f 05 } 		$a_01_2 = {25 73 5c 77 67 76 25 73 25 64 2e 65 78 65 00 } 		$a_03_3 = {6a 04 83 c7 0c 57 ff 74 24 24 ff 15 ?? ?? ?? ?? 8b 84 24 30 01 00 00 53 8d 4c 24 1c 51 83 c0 18 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}