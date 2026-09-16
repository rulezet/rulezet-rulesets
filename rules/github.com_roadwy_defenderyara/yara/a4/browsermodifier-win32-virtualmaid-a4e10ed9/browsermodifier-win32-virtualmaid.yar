rule BrowserModifier_Win32_VirtualMaid{
	meta:
		description = "BrowserModifier:Win32/VirtualMaid,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 20 4d 61 69 64 20 20 63 61 6e 27 74 20 72 65 74 72 69 76 65 20 69 6e 66 6f 6d 61 74 69 6f 6e 20 66 72 6f 6d } 		$a_00_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 72 00 73 00 64 00 6e 00 2e 00 72 00 75 00 2f 00 63 00 67 00 69 00 2d 00 62 00 69 00 6e 00 2f 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 65 00 78 00 65 00 3f 00 71 00 75 00 65 00 72 00 79 00 3d 00 } 	condition:
		((#a_01_0  & 1)*4+(#a_00_1  & 1)*3) >=7
 
}