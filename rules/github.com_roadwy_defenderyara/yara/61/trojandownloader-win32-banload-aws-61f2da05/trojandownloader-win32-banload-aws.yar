rule TrojanDownloader_Win32_Banload_AWS{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e 00 } 		$a_03_1 = {73 65 6c 65 63 74 20 67 75 61 72 64 61 ?? 20 66 72 6f 6d 20 72 6f 70 65 69 72 6f } 		$a_03_2 = {63 00 65 00 3d 00 53 00 51 00 4c 00 ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 53 00 6d 00 61 00 72 00 74 00 65 00 72 00 61 00 73 00 70 00 2e 00 6e 00 65 00 [0-10] 5c [0-10] 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}