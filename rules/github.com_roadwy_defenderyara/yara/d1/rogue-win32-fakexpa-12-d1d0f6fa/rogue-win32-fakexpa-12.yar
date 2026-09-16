rule Rogue_Win32_FakeXPA_12{
	meta:
		description = "Rogue:Win32/FakeXPA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 c0 09 8b 15 ?? ?? 40 00 2b d0 33 c9 8b 07 e8 ?? ?? ff ff 8d 55 fc b9 04 00 00 00 8b 07 e8 ?? ?? ff ff } 		$a_03_1 = {7e 29 8d 55 ef b9 01 00 00 00 8b 07 e8 ?? ?? ff ff a0 ?? ?? 40 00 30 45 ef 8d 55 ef b9 01 00 00 00 8b c6 e8 ?? ?? ff ff 4b 75 d7 } 		$a_03_2 = {83 e8 3a c1 e0 06 [0-10] e9 ?? 00 00 00 [0-10] 83 e8 3a c1 e0 0c [0-10] 90 04 01 02 eb e9 [0-10] 83 e8 3a c1 e0 12 } 		$a_00_3 = {58 50 61 6e 74 69 76 69 72 75 73 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}