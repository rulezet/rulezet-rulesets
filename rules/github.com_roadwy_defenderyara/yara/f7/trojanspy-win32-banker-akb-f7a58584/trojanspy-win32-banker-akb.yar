rule TrojanSpy_Win32_Banker_AKB{
	meta:
		description = "TrojanSpy:Win32/Banker.AKB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 41 00 56 00 41 00 53 00 54 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 00 00 } 		$a_01_1 = {64 00 61 00 74 00 61 00 63 00 61 00 64 00 61 00 73 00 74 00 72 00 6f 00 3d 00 } 		$a_01_2 = {2e 00 63 00 70 00 6c 00 2c 00 4d 00 6f 00 75 00 73 00 65 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}