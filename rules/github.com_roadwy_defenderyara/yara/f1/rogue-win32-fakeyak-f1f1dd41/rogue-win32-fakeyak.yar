rule Rogue_Win32_FakeYak{
	meta:
		description = "Rogue:Win32/FakeYak,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 50 68 69 73 68 69 6e 67 46 69 6c 74 65 72 00 45 6e 61 62 6c 65 64 } 		$a_03_1 = {69 64 3d 25 73 26 68 61 73 68 3d 00 50 4f 53 54 [0-05] 2f [0-05] 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}