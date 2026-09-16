rule Rogue_Win32_FakePowav_2{
	meta:
		description = "Rogue:Win32/FakePowav,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7c c6 8b 41 50 8b 49 34 8b 15 } 		$a_01_1 = {c6 04 29 68 8b 08 8d 14 2b 89 54 29 01 8b 10 6a 01 c6 44 2a 05 c3 } 		$a_01_2 = {73 6f 66 74 77 61 72 65 73 20 72 65 71 75 69 72 65 64 20 66 6f 72 20 76 69 72 75 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}