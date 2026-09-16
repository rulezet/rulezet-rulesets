rule BrowserModifier_Win32_ShieldSoftCby{
	meta:
		description = "BrowserModifier:Win32/ShieldSoftCby,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 53 65 74 74 69 6e 67 73 5c 46 46 44 65 66 53 65 61 72 63 68 2e 74 78 74 } 		$a_01_1 = {26 72 3d 37 30 30 31 26 67 65 6f 3d 55 53 26 70 74 61 67 3d 59 41 48 4f 4f 26 61 66 66 69 64 3d 79 61 68 6f 6f 26 61 70 70 3d 73 68 69 65 6c 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}