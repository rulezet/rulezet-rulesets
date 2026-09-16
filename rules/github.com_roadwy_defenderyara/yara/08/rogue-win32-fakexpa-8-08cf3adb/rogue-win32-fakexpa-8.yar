rule Rogue_Win32_FakeXPA_8{
	meta:
		description = "Rogue:Win32/FakeXPA,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {75 68 c6 45 e7 01 33 f6 8b 45 e8 8d 58 3c 8d 45 cc 50 8b 55 f8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c8 49 } 		$a_01_1 = {5b 46 4c 54 5d 00 00 00 ff ff ff ff 05 00 00 00 5b 50 4f 50 5d 00 } 		$a_01_2 = {5b 6b 65 79 5d 00 00 00 03 00 00 00 ff ff ff ff 06 00 00 00 3f 6e 69 63 6b 3d 00 } 		$a_01_3 = {5b 53 52 56 5d 3b 28 3f 69 29 } 		$a_01_4 = {5b 53 52 56 5d 00 00 00 ff ff ff ff 03 00 00 00 23 23 23 00 } 		$a_00_5 = {2f 62 75 79 2e 70 68 70 3f 69 64 3d 25 61 66 66 25 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_00_5  & 1)*1) >=5
 
}