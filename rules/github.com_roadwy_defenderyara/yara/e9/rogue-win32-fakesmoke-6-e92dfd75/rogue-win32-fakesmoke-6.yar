rule Rogue_Win32_FakeSmoke_6{
	meta:
		description = "Rogue:Win32/FakeSmoke,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 68 74 6d 6c 3f 67 65 74 3d fd 81 80 00 } 		$a_03_1 = {2f 54 52 41 4e 53 4c 41 54 45 00 64 6f 77 6e 6c 6f 61 64 00 fe 25 25 5c [0-28] 2e 65 78 65 } 		$a_03_2 = {2f 54 52 41 4e 53 4c 41 54 45 32 00 64 6f 77 6e 6c 6f 61 64 5f 71 75 69 65 74 00 fe 25 25 5c [0-28] 2e 65 78 65 } 		$a_03_3 = {2f 54 52 41 4e 53 4c 41 54 45 32 00 64 6f 77 6e 6c 6f 61 64 00 fe 25 25 5c [0-28] 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=11
 
}