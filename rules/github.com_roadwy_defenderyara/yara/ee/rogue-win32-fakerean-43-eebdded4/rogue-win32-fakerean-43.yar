rule Rogue_Win32_FakeRean_43{
	meta:
		description = "Rogue:Win32/FakeRean,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 68 74 74 70 73 73 2f 73 65 74 75 70 2e 70 68 70 3f 61 63 74 69 6f 6e 3d } 		$a_01_1 = {5c 73 65 74 75 70 2e 65 78 65 20 2d 70 22 31 35 3a 33 30 22 20 2d 79 20 2d 6f 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}