rule PWS_Win32_Zbot_3{
	meta:
		description = "PWS:Win32/Zbot,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5a 3a 5c 76 61 77 75 39 6f 67 67 76 2e 70 64 62 } 		$a_01_1 = {73 00 61 00 6c 00 61 00 75 00 62 00 68 00 2e 00 65 00 78 00 65 00 } 		$a_03_2 = {83 c4 0c a3 cc 67 49 00 8b 45 10 25 ff 00 00 00 88 45 ef 8b 45 0c 03 45 f8 0f b6 00 8b 4d 0c 03 4d f8 0f b6 09 33 c8 8b 45 0c 03 45 f8 88 08 ff 35 cc 67 49 00 ff 75 14 0f b6 45 ee 50 e8 ?? ?? ?? ?? 83 c4 0c a3 cc 67 49 00 ff 75 ef ff 75 ee e8 ?? ?? ?? ?? 59 59 0f b6 c0 8b 4d 0c 03 4d f8 0f b6 09 03 c8 8b 45 0c 03 45 f8 88 08 ff 35 cc 67 49 00 0f b6 45 ef 50 0f b6 45 ee 50 e8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}