rule PWS_Win32_Dyzap_J{
	meta:
		description = "PWS:Win32/Dyzap.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 e3 ff 00 00 00 0f b6 9b ?? ?? ?? ?? 33 14 9d ?? ?? ?? ?? 03 c1 89 16 03 f1 ff 4d f8 75 ?? 4f 83 e8 20 } 		$a_00_1 = {c7 06 0e 00 00 00 89 46 04 83 c1 02 0f b6 79 01 0f b6 19 c1 e7 08 0b fb 0f b6 59 ff c1 e7 08 0b fb 0f b6 59 fe c1 e7 08 0b fb 89 3c 90 42 83 c1 04 83 fa 08 } 		$a_03_2 = {0f b6 58 0d 0f b6 40 0c c1 e7 08 0b fb c1 e7 08 0b f8 33 79 0c 8b 45 08 83 c1 10 83 7d 0c 00 89 7d f8 0f 85 ?? ?? ?? ?? 8b 18 d1 fb } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}