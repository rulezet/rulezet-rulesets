rule VirTool_Win32_Injector_FS{
	meta:
		description = "VirTool:Win32/Injector.FS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2c 56 8b 4d ?? 03 4d ?? 88 01 eb 12 8b 55 ?? 03 55 ?? 8a 02 2c 98 } 		$a_01_1 = {6c 61 75 6e 63 68 } 		$a_01_2 = {70 72 6f 6d 70 74 2e 69 6e 69 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}