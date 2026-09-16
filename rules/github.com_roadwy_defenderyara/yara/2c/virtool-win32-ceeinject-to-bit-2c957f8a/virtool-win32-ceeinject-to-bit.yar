rule VirTool_Win32_CeeInject_TO_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TO!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 83 c4 08 8b d1 8a 12 80 f2 eb 88 10 ff 06 41 81 3e ?? ?? 00 00 75 } 		$a_01_1 = {55 8b ec 51 81 c2 ba 0a 00 00 89 55 fc 8b 7d fc ff d7 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}