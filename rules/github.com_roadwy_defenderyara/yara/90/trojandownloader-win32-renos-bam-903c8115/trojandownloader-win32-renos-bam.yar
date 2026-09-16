rule TrojanDownloader_Win32_Renos_BAM{
	meta:
		description = "TrojanDownloader:Win32/Renos.BAM,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {6d 61 64 43 72 79 70 74 00 } 		$a_01_1 = {4b 4f 4c 48 54 54 50 44 6f 77 6e 6c 6f 61 64 00 } 		$a_01_2 = {54 6c 48 65 6c 70 33 32 00 } 		$a_01_3 = {4d 50 47 55 6e 5a 49 50 00 } 		$a_01_4 = {4d 79 41 55 74 69 6c 73 00 } 		$a_01_5 = {41 64 77 61 72 65 55 74 69 6c 73 00 } 		$a_01_6 = {a1 b8 92 71 8c ef 11 de e1 78 17 73 cb 15 80 a8 67 52 60 a7 65 71 97 2a } 		$a_01_7 = {f3 50 d2 b7 eb 7c 0a eb c3 66 3d f6 50 80 62 85 78 d6 20 e1 0d c1 19 79 16 20 b6 16 8e ef 6d dc } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3) >=8
 
}