rule TrojanDropper_Win32_Zirit_D{
	meta:
		description = "TrojanDropper:Win32/Zirit.D,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {47 81 ff d0 07 00 00 7c c2 6a 00 e8 ?? ?? 00 00 8b 54 24 14 83 c4 04 2b c2 3d 60 54 00 00 89 44 24 10 73 79 6a 00 e8 ?? ?? 00 00 99 b9 14 00 00 00 83 c4 04 f7 f9 52 ff d5 } 		$a_01_1 = {50 68 02 00 00 80 ff d6 ba 00 97 49 01 8b 44 24 10 8d 04 80 8d 04 80 8d 0c 80 c1 e1 03 2b d1 52 ff d5 } 		$a_00_2 = {61 6e 74 69 76 25 73 25 73 00 00 69 69 72 75 73 } 		$a_00_3 = {4b 62 64 00 4d 6f 6e 00 57 69 6e 00 53 79 73 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*4+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}