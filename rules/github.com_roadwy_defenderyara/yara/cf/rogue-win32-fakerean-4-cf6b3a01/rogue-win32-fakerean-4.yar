rule Rogue_Win32_FakeRean_4{
	meta:
		description = "Rogue:Win32/FakeRean,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {32 54 1f ff 88 54 18 ff 43 4e 75 e9 } 		$a_01_1 = {8b 40 18 b9 73 00 00 00 ba a0 00 00 00 } 		$a_01_2 = {41 63 63 6f 72 64 69 6e 67 6c 79 20 74 6f 20 74 65 63 68 6e 69 63 61 6c 20 72 65 61 73 6f 6e } 		$a_01_3 = {50 6c 65 61 73 65 20 70 75 72 63 68 61 73 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}