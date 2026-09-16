rule VirTool_Win32_CeeInject_AAF_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAF!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff d7 8a 4d ?? 88 0e 46 88 5d ?? 3b f5 74 05 4d 3b f5 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}