rule PWS_Win32_OnLineGames_NZ_bit{
	meta:
		description = "PWS:Win32/OnLineGames.NZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {54 72 6f 6a 61 6e 44 4c 4c 2e 64 6c 6c [0-10] 48 6f 6f 6b } 		$a_01_1 = {53 65 74 48 6f 6f 6b 00 55 6e 48 6f 6f 6b 00 } 		$a_01_2 = {3f 61 74 3d 6c 6f 63 6b 26 73 31 33 3d } 		$a_01_3 = {26 74 62 42 61 6e 6b 50 77 64 3d } 		$a_01_4 = {22 6c 62 42 61 6e 6b 4d 6f 6e 65 79 22 3e } 		$a_01_5 = {22 6c 62 42 61 67 4d 6f 6e 65 79 22 3e } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}