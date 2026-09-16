rule Trojan_Win32_GhostRAT_MA_MTB_2{
	meta:
		description = "Trojan:Win32/GhostRAT.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 e4 f8 81 ec 5c 0b 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 58 0b 00 00 53 56 57 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15 } 		$a_01_1 = {5c 00 6a 00 69 00 73 00 75 00 70 00 64 00 66 00 2e 00 65 00 78 00 65 00 } 		$a_01_2 = {52 00 75 00 6e 00 4f 00 6e 00 6c 00 79 00 4f 00 6e 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}