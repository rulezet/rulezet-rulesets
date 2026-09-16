rule TrojanSpy_Win32_Bafi_Q_2{
	meta:
		description = "TrojanSpy:Win32/Bafi.Q,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 11 80 ca 20 03 c2 90 8d 49 02 66 39 19 75 f0 3d e0 1e 00 00 75 5e c7 44 3c 1c 01 00 00 80 } 		$a_00_1 = {00 61 64 6c 6c 2e 64 6c 6c 00 } 		$a_00_2 = {00 43 6c 6f 73 65 47 75 61 72 64 00 } 		$a_00_3 = {00 53 65 74 47 75 61 72 64 00 } 		$a_00_4 = {84 c0 74 11 66 83 f8 61 7c 04 66 83 e8 20 03 d0 c1 c2 03 eb } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}