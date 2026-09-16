rule TrojanDownloader_Win32_Zlob_APK{
	meta:
		description = "TrojanDownloader:Win32/Zlob.APK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {7d 14 8b 55 08 03 55 fc 8a 02 2c ?? 8b 4d 08 03 4d fc 88 01 } 		$a_00_1 = {69 35 69 2e 69 6e 2f 78 64 } 		$a_00_2 = {26 00 67 00 75 00 69 00 64 00 3d 00 } 		$a_00_3 = {69 70 64 6c 6c 2e 64 6c 6c 00 } 		$a_00_4 = {62 69 74 73 2e 64 6c 6c 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}