rule Rogue_Win32_FakeYak_7{
	meta:
		description = "Rogue:Win32/FakeYak,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 61 73 74 5f 75 70 64 61 74 65 5f 73 69 7a 65 00 } 		$a_01_1 = {75 70 64 61 74 65 2e 65 78 65 00 00 6f 70 65 6e 00 } 		$a_01_2 = {59 61 4b 72 65 76 65 64 6b 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}