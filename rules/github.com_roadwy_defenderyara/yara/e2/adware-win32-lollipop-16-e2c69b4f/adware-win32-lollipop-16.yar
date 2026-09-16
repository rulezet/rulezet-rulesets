rule Adware_Win32_Lollipop_16{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_03_0 = {ff d6 89 5d f0 80 7d ?? 4f 75 06 80 7d ?? 4b 74 1c } 		$a_01_1 = {c6 45 80 53 c6 45 81 74 c6 45 82 61 c6 45 83 72 c6 45 84 74 c6 45 85 4d c6 45 86 43 c6 45 87 00 } 		$a_01_2 = {c6 85 40 f7 ff ff 49 c6 85 41 f7 ff ff 4e c6 85 42 f7 ff ff 53 c6 85 43 f7 ff ff 54 c6 85 44 f7 ff ff 41 c6 85 45 f7 ff ff 4c c6 85 46 f7 ff ff 4c c6 85 47 f7 ff ff 3a } 		$a_01_3 = {4d 43 76 32 44 4c 4c 2e 64 6c 6c 00 53 74 61 72 74 4d 43 00 } 		$a_01_4 = {3c 5f 45 47 4d 43 5f 3e 00 } 		$a_01_5 = {26 67 72 70 69 64 3d 00 } 		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 66 63 6e 5c 78 30 30 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}