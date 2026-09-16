rule Rogue_Win32_FakeCog_2{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 47 39 00 00 8b 4a 1c eb 1a 8b 54 24 64 b8 07 11 00 00 8b 4a 20 eb 0c } 		$a_01_1 = {6d 61 6b 65 20 79 6f 75 72 20 50 43 20 66 75 6c 6c 20 73 63 61 6e 6e 69 6e 67 2e 3c 2f 62 72 } 		$a_03_2 = {d8 3d 87 88 90 09 0a 00 3f 00 00 00 3f 08 02 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1) >=3
 
}