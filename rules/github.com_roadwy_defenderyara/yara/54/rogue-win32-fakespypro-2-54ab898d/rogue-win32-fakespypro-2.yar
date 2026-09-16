rule Rogue_Win32_FakeSpypro_2{
	meta:
		description = "Rogue:Win32/FakeSpypro,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 10 8a 10 84 d2 74 0e 40 0f b6 d2 89 04 be 47 03 c2 3b c1 72 ec } 		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 41 76 53 63 61 6e } 		$a_01_2 = {70 72 6f 78 79 6c 73 70 2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}