rule Rogue_Win32_FakeYak_2{
	meta:
		description = "Rogue:Win32/FakeYak,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 22 8b 45 0c 8d 0c 06 8b 45 10 8a 14 07 30 11 50 47 ff 15 } 		$a_03_1 = {33 c9 0f b6 81 ?? ?? ?? ?? 8b d0 c1 ea 04 8a 92 ?? ?? ?? ?? 83 e0 0f } 		$a_01_2 = {ff 4c 24 18 0f 85 15 ff ff ff 38 5c 24 0f 74 10 68 e0 93 04 00 ff 15 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=2
 
}