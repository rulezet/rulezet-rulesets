rule VirTool_Win32_VBInject_gen_CE{
	meta:
		description = "VirTool:Win32/VBInject.gen!CE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f5 04 00 00 00 f5 58 59 59 59 59 40 ff 6c 6c ff } 		$a_01_1 = {6c b0 fe 6c a4 fe aa 71 9c fd } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}