rule Rogue_Win32_FakeCog{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 4c 24 4c 6a 00 51 6a 01 6a 04 ff 15 ?? ?? ?? ?? 6a 00 ff d6 50 } 		$a_01_1 = {7e 0c 80 7c 0c 18 5c 74 05 49 85 c9 7f f4 8b 94 24 20 11 00 00 8d 44 0c 19 } 		$a_01_2 = {63 6f 72 65 67 75 61 72 64 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}