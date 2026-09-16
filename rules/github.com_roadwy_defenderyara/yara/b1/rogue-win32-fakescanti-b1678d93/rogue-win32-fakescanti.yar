rule Rogue_Win32_FakeScanti{
	meta:
		description = "Rogue:Win32/FakeScanti,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 04 00 00 "
		
	strings :
		$a_13_0 = {3a 00 0f 85 90 16 c1 c0 90 00 01 } 		$a_83_1 = {08 0f 85 90 16 ff 75 1c 90 00 03 00 09 01 81 78 02 ec eb } 		$a_85_2 = {00 08 01 81 38 33 c0 c2 2c 0f 85 00 00 78 68 } 		$a_00_3 = {04 00 04 00 } 	condition:
		((#a_13_0  & 1)*1+(#a_83_1  & 1)*3072+(#a_85_2  & 1)*-28667+(#a_00_3  & 1)*0) >=2
 
}