rule VirTool_Win32_CeeInject_gen_KK_2{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KK,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 86 57 0d 00 68 88 4e 0d 00 e8 1a 00 00 00 89 45 fc 68 fa 8b 34 00 68 88 4e 0d 00 e8 08 00 00 00 89 45 f8 e9 ?? ?? ?? ?? 55 8b ec 53 56 57 51 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}