rule VirTool_Win32_Injector_FT_2{
	meta:
		description = "VirTool:Win32/Injector.FT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 00 07 00 01 00 8d 85 ?? ?? ff ff 83 c0 7d } 		$a_03_1 = {ff d0 83 ec 14 8b 85 ?? ?? ff ff 8b 50 28 8b 85 ?? ?? ff ff 01 c2 8b 85 ?? ?? ff ff 89 90 90 b0 00 00 00 } 		$a_01_2 = {43 72 65 61 4f 65 46 69 6c 65 41 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}