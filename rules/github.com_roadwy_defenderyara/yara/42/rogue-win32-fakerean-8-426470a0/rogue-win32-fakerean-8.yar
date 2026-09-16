rule Rogue_Win32_FakeRean_8{
	meta:
		description = "Rogue:Win32/FakeRean,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {8a 1b 83 c4 0c 80 fb e8 74 05 80 fb e9 75 0b } 		$a_02_1 = {2b cf 83 e8 05 83 e9 05 c6 86 ?? ?? ?? 00 e9 89 8e ?? ?? ?? 00 } 		$a_00_2 = {8a 14 10 30 94 0d fc fe ff ff 40 83 f8 14 } 		$a_03_3 = {6a 06 8b fa be ?? ?? ?? ?? 59 33 db f3 a6 74 ?? 83 c2 28 ff 45 fc 66 39 45 fc 72 e4 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}