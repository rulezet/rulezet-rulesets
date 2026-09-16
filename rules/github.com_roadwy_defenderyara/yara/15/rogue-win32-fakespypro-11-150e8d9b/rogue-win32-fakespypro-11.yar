rule Rogue_Win32_FakeSpypro_11{
	meta:
		description = "Rogue:Win32/FakeSpypro,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 00 68 00 ff ff ff 8b 4d fc 51 ff 15 ?? ?? ?? ?? 6a 00 8d 55 f4 52 68 00 01 00 00 } 		$a_03_1 = {f9 ff ff 51 8b ?? 08 8b ?? 08 8b ?? 08 8b ?? 08 8b ?? ?? 8b ?? 2c ff } 		$a_03_2 = {81 7d 0c fa 00 00 00 0f 85 ?? ?? 00 00 8b ?? 08 83 ?? 08 00 75 0a b8 05 40 00 80 e9 ?? ?? 00 00 8b ?? 1c 8b ?? 8b ?? 58 } 		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 41 00 76 00 53 00 63 00 61 00 6e 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}