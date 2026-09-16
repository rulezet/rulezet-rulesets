rule VirTool_Win32_CeeInject_MK_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MK!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4d a0 03 4d e4 8b 55 f0 03 55 bc 66 8b 01 66 89 02 8a 49 02 88 4a 02 } 		$a_03_1 = {8b 45 08 03 45 fc 0f b6 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 33 ca 8b 45 08 03 45 fc 88 08 eb } 		$a_03_2 = {7d 1b 8b 55 ?? 03 55 ?? 0f b6 02 8b 4d ?? 6b c9 ?? 33 c1 8b 55 ?? 03 55 ?? 88 02 eb } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}