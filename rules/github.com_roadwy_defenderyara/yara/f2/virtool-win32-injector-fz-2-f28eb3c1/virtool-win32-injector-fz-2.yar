rule VirTool_Win32_Injector_FZ_2{
	meta:
		description = "VirTool:Win32/Injector.FZ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 45 f8 ff 45 f8 81 7d f8 ?? ?? 00 00 7c f1 90 09 0e 00 c7 45 f8 } 		$a_01_1 = {b9 82 00 00 00 f3 a5 a4 } 		$a_01_2 = {b9 51 00 00 00 f3 a5 a4 } 		$a_01_3 = {00 53 74 65 72 6e 75 6d 00 5f 5f 5f 43 50 50 64 65 62 75 67 48 6f 6f 6b 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}