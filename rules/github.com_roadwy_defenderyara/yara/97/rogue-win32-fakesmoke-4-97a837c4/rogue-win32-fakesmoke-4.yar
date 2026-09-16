rule Rogue_Win32_FakeSmoke_4{
	meta:
		description = "Rogue:Win32/FakeSmoke,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 20 57 69 6e [0-01] (42 6c 75 65 53 6f 66 74|46 69 67 68 74 65 72) 00 } 		$a_01_1 = {2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 73 3d } 		$a_01_2 = {2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 70 3d } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}