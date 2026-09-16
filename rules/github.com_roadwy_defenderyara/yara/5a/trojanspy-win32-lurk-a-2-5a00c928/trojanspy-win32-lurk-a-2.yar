rule TrojanSpy_Win32_Lurk_A_2{
	meta:
		description = "TrojanSpy:Win32/Lurk.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 61 71 6c 3d 26 6f 71 3d } 		$a_01_1 = {25 73 25 73 25 64 2e 63 6d 64 00 } 		$a_01_2 = {7b 31 31 38 42 45 44 43 43 2d 41 39 30 31 2d 34 32 30 33 2d 42 34 46 32 2d 41 44 43 42 39 35 37 44 31 38 38 37 7d } 		$a_00_3 = {ff d3 6a 04 8d 45 fc 50 6a 05 57 ff d6 } 		$a_03_4 = {83 f8 50 75 05 33 c0 40 5e c3 56 ff 15 ?? ?? ?? ?? ff 74 24 08 ff 15 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}