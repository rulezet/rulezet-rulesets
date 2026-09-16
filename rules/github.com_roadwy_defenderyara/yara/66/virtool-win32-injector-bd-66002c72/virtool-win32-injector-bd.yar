rule VirTool_Win32_Injector_BD{
	meta:
		description = "VirTool:Win32/Injector.BD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {58 79 6c 69 74 6f 6c 20 6b 6e 6f 77 73 20 74 68 65 20 61 6e 73 77 65 72 2e } 		$a_01_1 = {42 74 77 2c 20 54 48 45 20 47 41 4d 45 2e } 		$a_01_2 = {28 59 6f 75 20 6a 75 73 74 20 6c 6f 73 74 20 69 74 2e 29 } 		$a_00_3 = {33 c9 b9 06 41 40 00 8a 01 3c 99 75 02 eb 0b 2b 05 04 10 40 00 88 01 41 eb ed } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}