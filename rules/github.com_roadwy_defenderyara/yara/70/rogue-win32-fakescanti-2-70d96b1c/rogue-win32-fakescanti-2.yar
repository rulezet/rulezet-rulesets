rule Rogue_Win32_FakeScanti_2{
	meta:
		description = "Rogue:Win32/FakeScanti,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 b8 00 00 40 00 50 45 00 00 75 22 66 81 b8 18 00 40 00 0b 01 75 17 83 b8 74 00 40 00 0e 76 0e 33 c9 39 88 e8 00 40 00 0f 95 c1 } 		$a_01_1 = {6f 72 50 20 65 63 69 6c 6f 50 20 73 77 6f 64 6e 69 57 } 		$a_01_2 = {57 44 65 66 65 6e 64 } 		$a_01_3 = {55 4e 50 52 4f 54 45 43 54 45 44 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}