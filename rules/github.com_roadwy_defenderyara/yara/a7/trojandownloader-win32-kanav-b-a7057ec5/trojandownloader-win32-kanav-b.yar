rule TrojanDownloader_Win32_Kanav_B{
	meta:
		description = "TrojanDownloader:Win32/Kanav.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 40 59 33 c0 8d bd ?? ?? ff ff f3 ab 66 ab aa 8d 85 ?? ?? ff ff 50 68 ?? ?? ?? ?? e8 } 		$a_00_1 = {38 31 41 36 41 38 44 32 30 43 41 32 41 45 } 		$a_00_2 = {2d 73 74 61 72 74 00 73 74 61 72 74 } 		$a_00_3 = {5c 41 59 4c 61 75 6e 63 68 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}