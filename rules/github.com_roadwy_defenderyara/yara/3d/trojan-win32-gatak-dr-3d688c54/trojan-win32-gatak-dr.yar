rule Trojan_Win32_Gatak_DR_{
	meta:
		description = "Trojan:Win32/Gatak.DR!!Gatak.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_01_0 = {c6 45 ec 6e c6 45 ed 74 c6 45 ee 64 c6 45 ef 6c c6 45 f0 6c c6 45 f1 2e c6 45 f2 64 c6 45 f3 6c c6 45 f4 6c } 		$a_01_1 = {74 06 81 f6 20 83 b8 ed d1 ea 4f 75 eb } 		$a_01_2 = {77 03 80 c2 20 38 54 35 ec 75 0f 46 41 41 83 fe 09 72 e3 } 		$a_03_3 = {68 eb 2f 76 e0 e8 ?? ?? ff ff 68 5e ce d6 e9 89 45 e8 e8 28 fb ff ff 68 f2 79 36 18 89 45 ec e8 ?? ?? ff ff } 		$a_01_4 = {e8 15 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e } 		$a_01_5 = {e8 11 00 00 00 77 77 77 2e 67 6f 6f 67 6c 65 2e } 		$a_01_6 = {e8 47 00 00 00 68 74 74 70 3a 2f 2f 68 6f 73 74 74 68 65 6e 70 6f 73 74 2e 6f 72 67 2f 75 70 6c 6f 61 64 73 2f } 		$a_01_7 = {2f 72 65 70 6f 72 74 5f 4e 5f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=3
 
}