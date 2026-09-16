rule VirTool_Win32_VBInject{
	meta:
		description = "VirTool:Win32/VBInject,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 00 33 00 4e 00 33 00 47 00 40 00 54 00 54 00 31 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}