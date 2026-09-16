rule Rogue_Win32_FakeRean_15{
	meta:
		description = "Rogue:Win32/FakeRean,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5b 41 6e 74 69 76 69 72 75 73 2e 6d 73 69 5d 0d 0a 54 79 70 65 3d 32 0d 0a 4c 6f 63 61 74 69 6f 6e 3d 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e [0-25] 2f 65 6e 2f 50 45 2f 41 6e 74 69 76 69 72 75 73 2e 6d 73 69 0d 0a 43 61 63 68 65 52 6f 6f 74 3d 32 38 0d 0a 43 61 63 68 65 46 6f 6c 64 65 72 3d 44 6f 77 6e 6c 6f 61 64 65 64 20 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 73 0d 0a 5b 53 65 74 75 70 2e 62 6d 70 5d 0d 0a 54 79 70 65 3d 30 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}