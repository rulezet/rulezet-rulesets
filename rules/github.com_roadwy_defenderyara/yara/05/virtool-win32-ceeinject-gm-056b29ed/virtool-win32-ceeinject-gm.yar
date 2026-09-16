rule VirTool_Win32_CeeInject_GM{
	meta:
		description = "VirTool:Win32/CeeInject.GM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 ?? ?? ?? 00 0f b6 44 24 f1 3c ff 75 02 eb 1b c1 e0 15 74 fb c1 e3 02 ff e1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}