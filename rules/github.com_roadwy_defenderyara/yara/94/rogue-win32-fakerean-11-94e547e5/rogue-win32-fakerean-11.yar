rule Rogue_Win32_FakeRean_11{
	meta:
		description = "Rogue:Win32/FakeRean,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ac 3c 41 72 06 3c 5a 77 02 04 20 aa e2 f2 81 7d ?? 6b 65 72 6e 75 c7 81 7d ?? 65 6c 33 32 75 be 81 7d ?? 2e 64 6c 6c 75 } 		$a_00_1 = {66 69 6c 65 62 6c 6f 62 44 65 73 74 72 6f 79 3a 20 25 73 20 6e 6f 74 20 73 61 76 65 64 3a 20 72 65 70 6f 72 74 20 74 6f 20 68 74 74 70 3a 2f 2f 62 75 67 73 2e 63 6c 61 6d 61 76 2e 6e 65 74 } 		$a_00_2 = {6c 69 62 43 6c 61 6d 41 56 2e 64 6c 6c 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}