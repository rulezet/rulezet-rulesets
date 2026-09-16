rule Rogue_Win32_FakeAdpro_2{
	meta:
		description = "Rogue:Win32/FakeAdpro,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 2d 56 69 72 75 73 2d 50 72 6f 2e 69 6e 73 74 61 6c 6c 00 } 		$a_01_1 = {3f 61 63 74 69 6f 6e 3d 67 65 74 5f 64 65 6d 6f 00 } 		$a_01_2 = {3f 61 63 74 69 6f 6e 3d 67 65 74 5f 69 64 00 } 		$a_01_3 = {41 6e 74 69 2d 56 69 72 75 73 2d 50 72 6f 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 69 6e 73 74 61 6c 65 64 2e 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}