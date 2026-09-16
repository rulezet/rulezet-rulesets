rule VirTool_Win32_Injector{
	meta:
		description = "VirTool:Win32/Injector,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 59 0d 33 d2 8b c7 f7 f3 8a 59 0c 8a c2 f6 69 0e 8a 16 02 c3 32 d0 88 16 8b 41 04 46 47 3b f8 72 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}