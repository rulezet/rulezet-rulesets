rule Rogue_Win32_FakePAV_3{
	meta:
		description = "Rogue:Win32/FakePAV,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {29 f1 d1 e9 29 ca 76 ?? 01 d1 29 d6 66 b8 30 00 29 d6 eb ?? 66 89 04 56 4a 75 } 		$a_00_1 = {70 68 69 73 68 69 6e 67 } 		$a_01_2 = {4d 6f 6e 65 79 46 6c 61 74 49 6e 61 63 74 69 76 65 43 6f 6c 6f 72 } 		$a_01_3 = {68 74 74 70 50 61 79 66 6f 72 6d } 		$a_00_4 = {74 6f 72 72 65 6e 74 73 } 	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=14
 
}