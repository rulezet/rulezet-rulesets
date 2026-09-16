rule VirTool_Win32_CeeInject_ML_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ML!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c b6 b8 ?? ?? ?? ?? c1 e1 ?? 2b ce c1 e1 ?? f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b fa 8d 14 f6 8d 04 d6 8a 4c 3c ?? c1 e0 ?? 03 c6 80 f1 ?? 8d 34 c0 b8 ?? ?? ?? ?? f7 ee c1 fa ?? 8b c2 c1 e8 ?? 03 d0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}