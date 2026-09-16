rule TrojanSpy_Win32_Banbra_M{
	meta:
		description = "TrojanSpy:Win32/Banbra.M,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {3e 3e 20 42 61 6e 6b 20 4e 61 6d 65 20 2d 20 00 3e 3e 20 43 6c 69 70 42 6f 61 72 64 20 2d 20 00 } 		$a_01_1 = {21 4d 63 2e 41 66 65 65 21 00 } 		$a_01_2 = {26 63 6f 6e 74 65 6e 74 32 3d 00 } 		$a_01_3 = {6b 65 79 2e 6c 6f 67 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}