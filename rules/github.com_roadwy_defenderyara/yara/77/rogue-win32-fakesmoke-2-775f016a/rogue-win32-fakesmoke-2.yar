rule Rogue_Win32_FakeSmoke_2{
	meta:
		description = "Rogue:Win32/FakeSmoke,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 68 74 6d 6c 3f 67 65 74 3d } 		$a_01_1 = {2f 54 52 41 4e 53 4c 41 54 45 32 00 64 6f 77 6e 6c 6f 61 64 00 } 		$a_01_2 = {56 69 72 69 69 20 50 72 6f 74 65 63 74 69 6f 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}