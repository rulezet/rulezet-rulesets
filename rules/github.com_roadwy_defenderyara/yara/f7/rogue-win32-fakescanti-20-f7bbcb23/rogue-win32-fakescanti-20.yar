rule Rogue_Win32_FakeScanti_20{
	meta:
		description = "Rogue:Win32/FakeScanti,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 6c 75 65 46 6c 61 72 65 20 41 6e 74 69 76 69 72 75 73 } 		$a_01_1 = {52 75 6e 6e 69 6e 67 20 6f 66 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 69 73 20 69 6d 70 6f 73 73 69 62 6c 65 } 		$a_01_2 = {61 63 74 69 6f 6e 2e 70 68 70 3f 70 3d 25 64 26 69 64 3d 25 73 26 73 79 73 74 65 6d 3d 25 73 26 68 77 69 64 3d 25 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}