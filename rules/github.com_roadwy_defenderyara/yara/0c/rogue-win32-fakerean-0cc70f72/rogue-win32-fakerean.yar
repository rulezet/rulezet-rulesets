rule Rogue_Win32_FakeRean{
	meta:
		description = "Rogue:Win32/FakeRean,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {0f b6 54 04 14 } 		$a_01_1 = {0f b6 4c 14 14 } 		$a_01_2 = {8a 4c 04 14 } 		$a_01_3 = {68 00 6e 3f 00 } 		$a_01_4 = {05 c0 0f 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}