rule Rogue_Win32_FakeRean_44{
	meta:
		description = "Rogue:Win32/FakeRean,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 6c 6f 67 73 32 2f 6c 6f 67 2e 70 68 70 3f 68 6f 73 74 69 64 3d } 		$a_01_1 = {53 70 72 65 61 64 20 66 69 6e 69 73 68 65 64 } 		$a_01_2 = {43 4d 75 6c 74 69 4b 65 79 41 75 74 6f 72 75 6e } 		$a_01_3 = {72 65 70 6f 72 74 20 75 72 6c 20 5b 25 73 5d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}