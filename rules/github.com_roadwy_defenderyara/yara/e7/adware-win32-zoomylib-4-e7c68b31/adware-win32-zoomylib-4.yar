rule Adware_Win32_ZoomyLib_4{
	meta:
		description = "Adware:Win32/ZoomyLib,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 74 00 61 00 6d 00 6d 00 67 00 31 00 31 00 } 		$a_01_1 = {83 7d 24 26 74 16 83 7d 24 03 74 10 83 7d 24 25 74 0a 83 7d 24 0c 0f 85 d7 02 00 00 8b 45 1c 89 85 f8 fb ff ff 83 a5 e8 fb ff ff 00 68 4f 46 49 52 68 00 04 00 00 6a 01 ff 15 } 		$a_03_2 = {55 8b ec 51 c7 45 fc 65 03 00 c0 e8 ?? ?? ?? ?? 0f b6 c0 85 c0 74 34 e8 ?? ?? ?? ?? 0f b6 c0 85 c0 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}