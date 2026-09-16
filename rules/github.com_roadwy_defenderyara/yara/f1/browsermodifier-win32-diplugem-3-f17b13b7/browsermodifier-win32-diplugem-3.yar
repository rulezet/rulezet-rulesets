rule BrowserModifier_Win32_Diplugem_3{
	meta:
		description = "BrowserModifier:Win32/Diplugem,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {51 68 de c0 ad de e8 } 		$a_01_1 = {52 68 ca da 3e 30 e8 } 		$a_03_2 = {83 c1 02 d1 e9 8d 14 8d 04 00 00 00 89 55 ?? 8b 45 ?? 8b 4d ?? 8d 54 01 02 52 6a 00 ff 15 } 		$a_01_3 = {33 37 33 35 39 32 39 30 35 34 20 38 30 39 34 32 35 36 31 30 } 		$a_01_4 = {2f 70 69 64 3d } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}