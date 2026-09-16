rule Trojan_Win32_Emotet_DI{
	meta:
		description = "Trojan:Win32/Emotet.DI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {78 00 6f 00 32 00 2a 00 57 00 36 00 79 00 40 00 64 00 2f 00 6d 00 3c 00 23 00 } 		$a_01_1 = {47 43 57 59 71 31 67 2e 70 64 62 } 		$a_01_2 = {3d 20 3d 24 3d 28 3d 2c 3d 30 3d 34 3d 38 3d 3c 3d 40 3d 44 3d 48 3d 4c 3d 50 3d 54 3d 58 3d 5c 3d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}