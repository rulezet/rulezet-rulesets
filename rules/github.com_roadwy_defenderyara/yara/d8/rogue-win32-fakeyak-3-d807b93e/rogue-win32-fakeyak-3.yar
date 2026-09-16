rule Rogue_Win32_FakeYak_3{
	meta:
		description = "Rogue:Win32/FakeYak,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 55 10 03 55 fc 0f be 02 8b 4d 08 03 4d f8 0f be 11 33 d0 8b 45 08 03 45 f8 88 10 8b 4d fc 83 c1 01 89 4d fc 8b 55 10 52 e8 } 		$a_01_1 = {7b 63 6f 69 64 7d } 		$a_01_2 = {7b 61 66 66 69 64 7d } 		$a_01_3 = {2f 63 6f 6d 70 61 74 69 62 69 6c 69 74 79 61 70 70 6c 69 65 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}