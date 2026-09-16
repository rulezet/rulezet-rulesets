rule VirTool_Win32_Injector_gen_DP{
	meta:
		description = "VirTool:Win32/Injector.gen!DP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6b ff 28 01 fb 89 9c 24 a4 04 00 00 ff b4 24 94 04 00 00 } 		$a_01_1 = {8d 6c 24 48 0f bf 45 06 39 c3 0f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}