rule VirTool_Win32_Ceeinject_TJ_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.TJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 03 8a 00 34 7b 8b 15 ?? ?? ?? ?? 03 13 88 02 90 90 ff 03 81 3b 5d 57 00 00 75 e0 90 09 05 00 a1 } 		$a_01_1 = {8b 03 40 bf 8a 00 00 00 33 d2 f7 f7 8b c1 03 03 88 10 90 ff 03 81 3b 57 b9 46 22 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}