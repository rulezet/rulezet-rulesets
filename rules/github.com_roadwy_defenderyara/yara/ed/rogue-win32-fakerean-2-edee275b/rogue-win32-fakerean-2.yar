rule Rogue_Win32_FakeRean_2{
	meta:
		description = "Rogue:Win32/FakeRean,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 7f 05 75 05 51 04 05 89 05 2b 8e 05 89 79 04 8d 8c 44 0e 08 d0 6c c7 45 dc 81 6d c7 24 45 e0 } 		$a_01_1 = {89 79 04 8d 8c 0e 22 08 d0 6c c7 45 dc 81 6d c7 45 92 e0 51 2a eb 23 60 06 89 d6 21 37 82 f2 d0 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}