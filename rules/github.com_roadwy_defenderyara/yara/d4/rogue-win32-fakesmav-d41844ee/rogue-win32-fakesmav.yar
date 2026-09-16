rule Rogue_Win32_FakeSmav{
	meta:
		description = "Rogue:Win32/FakeSmav,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ab e2 f7 c3 90 09 06 00 ad 35 } 		$a_03_1 = {74 39 2d 00 04 00 00 2d 00 04 00 00 2d 00 08 00 00 eb e0 90 09 0d 00 8b ?? 81 ?? ?? ?? ?? ?? 66 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}