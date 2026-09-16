rule Adware_Win32_ZoomyLib_6{
	meta:
		description = "Adware:Win32/ZoomyLib,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 40 30 0f b6 40 02 89 45 fc 39 7d fc 74 0e 68 20 4e 00 00 56 ff 15 ?? ?? ?? ?? eb 05 e8 0c 00 00 00 39 7d fc 75 d3 57 e8 ?? ?? ?? ?? cc 55 81 ec 10 04 00 00 8d 6c 24 fc a1 ?? ?? ?? ?? 33 c5 89 85 10 04 00 00 6a 04 } 		$a_03_1 = {8b 75 f0 56 ff 15 ?? ?? ?? ?? 85 c0 74 12 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 85 c0 74 02 ff d0 } 		$a_01_2 = {83 c6 f0 83 c9 ff 89 4d fc 8d 46 0c f0 0f c1 08 49 85 c9 7f 08 8b 0e 56 8b 01 ff 50 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}