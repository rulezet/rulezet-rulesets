rule VirTool_Win32_VBInject_AEE_2{
	meta:
		description = "VirTool:Win32/VBInject.AEE,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 02 00 00 "
		
	strings :
		$a_03_0 = {52 6a 02 ff 15 ?? ?? ?? 00 83 c4 0c c7 45 fc 08 00 00 00 eb } 		$a_03_1 = {00 eb 0f 8b 55 ?? 03 55 ?? 0f 80 ?? ?? ?? 00 89 55 ?? 8b 45 ?? 3b 45 ?? 7f 90 09 14 00 c7 45 ?? ?? ?? ?? ?? c7 45 ?? 01 00 00 00 c7 45 ?? 00 00 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=100
 
}