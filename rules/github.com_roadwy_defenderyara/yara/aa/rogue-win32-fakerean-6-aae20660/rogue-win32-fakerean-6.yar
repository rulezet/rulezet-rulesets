rule Rogue_Win32_FakeRean_6{
	meta:
		description = "Rogue:Win32/FakeRean,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 44 52 5f 00 00 00 00 68 74 74 70 64 73 63 6f 6e 66 69 67 2e 63 6f 6d 00 00 00 00 68 74 74 70 73 68 69 67 68 2e 69 6e 00 } 		$a_01_1 = {6d 2e 32 00 4f 4b 00 00 31 00 } 		$a_01_2 = {2e 63 70 6c 00 } 		$a_01_3 = {44 69 61 6c 65 72 69 42 6c 6f 63 6b 65 72 74 72 61 79 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}