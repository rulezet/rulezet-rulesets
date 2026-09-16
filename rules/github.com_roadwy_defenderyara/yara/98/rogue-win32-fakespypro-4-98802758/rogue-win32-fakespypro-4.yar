rule Rogue_Win32_FakeSpypro_4{
	meta:
		description = "Rogue:Win32/FakeSpypro,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 02 53 6a f0 56 ff 15 } 		$a_01_1 = {eb 67 ff 45 fc 83 7d fc 0a 75 4b } 		$a_03_2 = {85 d2 75 3c 8b c6 6b c0 0c 8b 88 ?? ?? ?? ?? 8b 90 90 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? 89 44 } 		$a_03_3 = {74 39 50 57 e8 ?? ?? ?? ?? 59 59 85 c0 74 36 83 c6 0c } 		$a_01_4 = {37 61 1d 02 a4 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}