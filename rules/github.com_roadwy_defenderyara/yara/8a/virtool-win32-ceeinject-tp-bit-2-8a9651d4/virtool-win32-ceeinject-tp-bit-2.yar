rule VirTool_Win32_CeeInject_TP_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 04 3e 6a 00 90 09 05 00 e8 ?? ff ff ff } 		$a_03_1 = {8b c8 0f af 0d ?? ?? ?? ?? e8 ?? ff ff ff 03 c8 89 0d ?? ?? ?? ?? e8 ?? ff ff ff 0f b7 15 ?? ?? ?? ?? 23 c2 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}