rule Rogue_Win32_FakePAV_4{
	meta:
		description = "Rogue:Win32/FakePAV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {29 f1 d1 e9 09 d2 78 1a 29 ca 76 16 29 d6 66 b8 ?? 00 29 d6 01 d1 eb ?? 66 89 04 56 4a } 		$a_01_1 = {64 66 65 72 74 74 65 72 32 33 34 32 7a 63 } 		$a_01_2 = {7a 78 63 7a 63 7a 78 63 } 		$a_01_3 = {4d 6f 6e 65 79 46 6c 61 74 49 6e 61 63 74 69 76 65 43 6f 6c 6f 72 } 		$a_00_4 = {6d 73 63 6f 6e 66 69 67 00 6d 62 61 6d 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}