rule Rogue_Win32_FakeVimes{
	meta:
		description = "Rogue:Win32/FakeVimes,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 69 64 3d 25 73 26 77 76 3d 25 73 } 		$a_01_1 = {55 73 65 72 49 44 3d 25 73 26 77 76 3d 25 73 } 		$a_01_2 = {69 65 78 70 6c 2a 20 2f 49 4d } 		$a_01_3 = {68 6f 73 74 73 2e 6f 31 64 } 		$a_01_4 = {56 69 72 75 73 20 44 6f 63 74 6f 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}