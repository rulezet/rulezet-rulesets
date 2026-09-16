rule Rogue_Win32_FakeRean_13{
	meta:
		description = "Rogue:Win32/FakeRean,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 0f be 88 00 e0 40 00 8b 55 fc 83 c2 01 33 55 f8 2b ca 8b 45 fc 88 88 00 e0 40 00 8b 4d fc 83 c1 01 89 4d fc } 		$a_00_1 = {70 61 75 73 65 00 00 00 45 6e 74 65 72 20 74 65 78 74 2e 20 49 6e 63 6c 75 64 65 20 61 20 64 6f 74 20 28 27 2e 27 29 20 69 6e 20 61 20 73 65 6e 74 65 6e 63 65 20 74 6f 20 65 78 69 74 3a 00 00 43 68 61 72 61 63 74 65 72 73 3a 20 25 63 20 25 63 20 0a 00 44 65 63 69 6d 61 6c 73 3a 20 25 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}