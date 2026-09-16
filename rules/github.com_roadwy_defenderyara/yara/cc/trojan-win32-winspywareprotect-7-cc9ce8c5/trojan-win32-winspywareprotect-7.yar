rule Trojan_Win32_WinSpywareProtect_7{
	meta:
		description = "Trojan:Win32/WinSpywareProtect,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 32 42 44 2d 41 38 43 42 2d 37 45 35 } 		$a_01_1 = {3a 2f 2f 64 6c 2e 25 73 2f 67 65 74 2f 3f 70 69 6e 3d } 		$a_01_2 = {2f 73 63 61 6e 2e } 		$a_01_3 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}