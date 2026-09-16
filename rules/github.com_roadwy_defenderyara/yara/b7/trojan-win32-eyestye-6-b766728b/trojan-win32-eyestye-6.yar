rule Trojan_Win32_EyeStye_6{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 61 6d 65 3d 22 73 65 63 6b 65 79 22 } 		$a_03_1 = {3f 70 6c 5f 6e 61 6d 65 3d [0-08] 26 75 69 64 3d } 		$a_01_2 = {64 61 74 61 73 68 69 74 3d } 		$a_02_3 = {8b f0 81 7d fc c8 00 00 00 76 ?? 8b [0-15] 8b c6 e8 ?? ?? ?? ?? 8b f8 8d ?? ?? 50 8b cf ba 50 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}