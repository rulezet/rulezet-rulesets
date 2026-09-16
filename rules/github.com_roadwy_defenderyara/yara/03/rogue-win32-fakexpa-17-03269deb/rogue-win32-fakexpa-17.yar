rule Rogue_Win32_FakeXPA_17{
	meta:
		description = "Rogue:Win32/FakeXPA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {80 7c 02 ff 21 75 1a 8b 45 fc e8 ?? ?? ff ff 8b d0 8d 45 fc b9 01 00 00 00 e8 ?? ?? ff ff ff 45 e8 4b 75 d1 } 		$a_02_1 = {83 e2 3f 8b cf c1 e1 03 8d 0c cd ?? ?? ?? ?? 0f b6 14 11 8b 4d ec 83 e1 c0 0b d1 e8 ?? ?? ff ff 8b 55 e0 8b 45 f8 e8 ?? ?? ff ff 8b 45 f8 83 ff 0f 75 04 33 ff eb 01 47 c1 ee 08 ff 4d f4 75 b0 } 		$a_02_2 = {8d 83 8c 05 00 00 e8 ?? ?? ff ff 8b 4b 28 e3 10 ff b3 8c 05 00 00 6a 00 6a 0c 51 e8 ?? ?? ff ff 0f b6 8b c2 00 00 00 e2 07 89 d8 e8 ?? ?? 00 00 93 5b ff b0 00 01 00 00 c3 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}