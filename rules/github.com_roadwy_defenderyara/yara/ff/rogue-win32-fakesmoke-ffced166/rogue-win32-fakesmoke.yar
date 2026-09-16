rule Rogue_Win32_FakeSmoke{
	meta:
		description = "Rogue:Win32/FakeSmoke,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e 70 68 74 6d 6c 3f 67 65 74 3d fd 81 80 00 fe 25 25 5c [0-28] 2e 65 78 65 } 		$a_01_1 = {2f 54 52 41 4e 53 4c 41 54 45 32 00 64 6f 77 6e 6c 6f 61 64 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}