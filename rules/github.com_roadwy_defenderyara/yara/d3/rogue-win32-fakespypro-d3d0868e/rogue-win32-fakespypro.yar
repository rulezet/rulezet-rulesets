rule Rogue_Win32_FakeSpypro{
	meta:
		description = "Rogue:Win32/FakeSpypro,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {96 58 b9 e7 bf 35 02 01 ca 81 e9 03 bb 35 02 81 c6 21 bd 38 00 81 c6 df ea 0d 00 89 f2 fc 89 f7 52 e9 77 ff ff ff 2d ?? ?? ?? ?? 41 49 e8 72 ff ff ff 83 e9 0a 83 c1 09 85 c9 75 e5 c3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}