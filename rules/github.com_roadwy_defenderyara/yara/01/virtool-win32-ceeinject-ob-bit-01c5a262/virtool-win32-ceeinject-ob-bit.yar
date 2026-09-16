rule VirTool_Win32_CeeInject_OB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 04 07 88 45 ?? 8b 45 ?? 0f af 45 } 		$a_03_1 = {8a 4d dc 75 03 8a 4d ?? 88 0c 17 } 		$a_03_2 = {84 c0 75 0d 0f b6 0d ?? ?? ?? ?? 0f af c8 29 4d ?? 32 5d } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}