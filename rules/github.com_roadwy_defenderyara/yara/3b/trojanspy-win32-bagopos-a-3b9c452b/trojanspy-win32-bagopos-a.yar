rule TrojanSpy_Win32_Bagopos_A{
	meta:
		description = "TrojanSpy:Win32/Bagopos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 49 6e 73 74 61 6c 6c 48 6f 6f 6b 73 00 [0-05] 52 65 6d 6f 76 65 48 6f 6f 6b 73 00 } 		$a_01_1 = {44 00 4c 00 4c 00 78 00 36 00 34 00 2e 00 64 00 6c 00 6c 00 } 		$a_03_2 = {8a 06 3c 3d 75 1a ba 01 00 00 00 8b ce e8 ?? ?? ?? ?? ba 02 00 00 00 8b ce e8 ?? ?? ?? ?? eb 3c 3c 5e 75 1d ba 01 00 00 00 } 		$a_03_3 = {80 f9 30 72 0d 80 f9 39 77 08 40 83 f8 14 7c ?? eb 05 83 f8 0d 7c } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}