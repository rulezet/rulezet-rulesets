rule Trojan_Win32_Redline_MA_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 ?? ?? ?? ?? 88 0c 02 c9 c2 } 		$a_03_1 = {8b 45 d8 01 45 f0 8d 04 3e 89 45 f4 8b c7 c1 e8 05 83 3d ?? ?? ?? ?? 1b 89 45 0c 75 ?? 33 c0 50 50 50 ff 15 } 		$a_01_2 = {55 6e 6c 6f 63 6b 46 69 6c 65 } 		$a_01_3 = {44 65 6c 65 74 65 46 69 6c 65 57 } 		$a_01_4 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 45 78 41 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}