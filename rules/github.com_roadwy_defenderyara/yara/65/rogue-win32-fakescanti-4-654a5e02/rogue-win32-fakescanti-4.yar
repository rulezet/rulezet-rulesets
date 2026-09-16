rule Rogue_Win32_FakeScanti_4{
	meta:
		description = "Rogue:Win32/FakeScanti,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3c 58 74 0c 50 6a 01 8d 4c 24 ?? e8 90 09 07 00 0f b6 86 } 		$a_01_1 = {81 b8 00 00 40 00 50 45 00 00 75 22 66 81 b8 18 00 40 00 0b 01 75 17 83 b8 74 00 40 00 0e 76 0e 33 c9 39 88 e8 00 40 00 0f 95 c1 } 		$a_01_2 = {64 62 73 69 6e 69 74 2e 65 78 65 } 		$a_01_3 = {55 4e 50 52 4f 54 45 43 54 45 44 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=4
 
}