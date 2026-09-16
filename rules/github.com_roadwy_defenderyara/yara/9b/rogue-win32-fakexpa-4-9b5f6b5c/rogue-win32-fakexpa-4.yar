rule Rogue_Win32_FakeXPA_4{
	meta:
		description = "Rogue:Win32/FakeXPA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b7 51 12 0f 84 0f 00 00 00 64 8f 05 00 00 00 00 81 c4 04 00 00 00 61 c3 90 09 05 00 ff ?? ?? 81 } 		$a_03_1 = {b8 f4 0f 84 0f 00 00 00 64 8f 05 00 00 00 00 81 c4 04 00 00 00 61 c3 90 09 07 00 ff ?? ?? 81 ?? 90 90 90 90 } 		$a_01_2 = {8b 00 81 f8 83 fa 08 0f 0f 84 0f 00 00 00 64 8f 05 00 00 00 00 81 c4 04 00 00 00 61 c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}