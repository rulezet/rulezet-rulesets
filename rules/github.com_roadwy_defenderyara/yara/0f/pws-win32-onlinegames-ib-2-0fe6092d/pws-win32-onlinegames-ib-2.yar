rule PWS_Win32_OnLineGames_IB_2{
	meta:
		description = "PWS:Win32/OnLineGames.IB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {44 54 4d 42 3a 00 } 		$a_00_1 = {50 41 53 41 3a 00 } 		$a_00_2 = {25 73 5c 6a 61 76 61 5c 74 72 75 73 74 6c 69 62 5c 25 73 00 } 		$a_00_3 = {3f 64 6f 3d 74 72 26 63 3d 71 26 69 3d 25 73 } 		$a_03_4 = {83 f8 03 74 05 83 f8 04 75 ?? 68 20 40 00 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*2) >=4
 
}