rule VirTool_Win32_Injector_FT{
	meta:
		description = "VirTool:Win32/Injector.FT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 07 07 00 01 00 ff d6 8b 4c 24 ?? 57 51 ff d0 } 		$a_03_1 = {83 c0 34 50 8b 44 24 ?? 83 c2 08 52 50 ff 54 24 ?? 8b 4c 24 ?? 8b 51 28 03 54 24 } 		$a_01_2 = {52 65 76 64 46 69 6c 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}