rule Backdoor_Win32_Moudoor_A_2{
	meta:
		description = "Backdoor:Win32/Moudoor.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 83 c2 01 89 55 f8 8b 45 f8 3b 45 f4 7d 2e 8b 4d fc 03 4d f8 0f be 11 81 ea ?? 00 00 00 8b 45 fc 03 45 f8 88 10 90 90 8b 4d fc 03 4d f8 0f be 11 83 f2 ?? 8b 45 fc 03 45 f8 88 10 } 		$a_03_1 = {8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 f8 73 26 8b 4d ?? 03 4d fc 33 d2 8a 11 8b ca 8b 45 fc 99 be ?? 00 00 00 f7 fe 83 c2 ?? 33 ca 8b 55 ?? 03 55 fc 88 0a eb c9 } 		$a_01_2 = {55 70 64 61 74 65 57 69 6e 64 6f 77 00 00 00 00 61 75 74 6f 2e 64 61 74 } 		$a_01_3 = {68 6f 73 74 2e 65 78 65 00 4d 69 63 72 6f 73 6f 66 74 20 55 70 64 61 74 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}