rule Trojan_Win32_Ropest_E{
	meta:
		description = "Trojan:Win32/Ropest.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 c0 51 2d 9e cc c1 c0 0f 69 c0 93 35 87 1b } 		$a_01_1 = {41 53 54 45 52 4f 50 45 5f 43 4c 49 43 4b 45 52 5f 4d 55 54 45 58 00 } 		$a_00_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 69 76 65 6a 6f 75 72 6e 61 6c 2e 63 6f 6d 2f 73 65 61 72 63 68 2f 3f 68 6f 77 3d 74 6d 26 61 72 65 61 3d 64 65 66 61 75 6c 74 26 71 3d 25 73 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}