rule VirTool_Win32_CobaltStrike_A_5{
	meta:
		description = "VirTool:Win32/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 } 		$a_01_1 = {eb 86 5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 31 ff 57 57 57 57 57 68 3a 56 79 a7 ff d5 } 		$a_03_2 = {eb 86 5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 00 29 c4 54 50 68 29 80 6b 00 ff d5 50 [0-08] 50 68 ea 0f df e0 ff d5 } 		$a_01_3 = {eb 86 5d 31 c0 6a 40 b4 10 68 00 10 00 00 68 ff ff 07 00 6a 00 68 58 a4 53 e5 ff d5 83 c0 40 89 c7 50 31 c0 b0 70 b4 69 50 68 64 6e 73 61 54 68 4c 77 26 07 ff d5 } 		$a_01_4 = {68 58 a4 53 e5 ff d5 50 e9 a8 00 00 00 5a 31 c9 51 51 68 00 b0 04 00 68 00 b0 04 00 6a 01 6a 06 6a 03 52 68 45 70 df d4 ff d5 50 8b 14 24 6a 00 52 68 28 6f 7d e2 ff d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}