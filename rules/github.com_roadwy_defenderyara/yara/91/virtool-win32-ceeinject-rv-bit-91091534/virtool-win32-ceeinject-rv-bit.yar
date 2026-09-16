rule VirTool_Win32_CeeInject_RV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RV!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 fc 0f 1f 84 00 00 00 00 00 55 89 e5 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}