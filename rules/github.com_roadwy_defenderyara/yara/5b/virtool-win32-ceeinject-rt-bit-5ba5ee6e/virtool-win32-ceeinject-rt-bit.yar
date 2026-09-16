rule VirTool_Win32_CeeInject_RT_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {30 01 69 c0 ?? ?? ?? ?? ff 4d 0c 05 ?? ?? ?? ?? 41 83 7d 0c 00 77 e9 } 		$a_03_1 = {8b 54 24 04 33 c0 eb ?? 0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 } 		$a_03_2 = {88 45 08 8a 45 fe 8a c8 c0 f9 ?? c0 e0 ?? 02 45 ff 80 e1 ?? c0 e2 ?? 32 ca } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}