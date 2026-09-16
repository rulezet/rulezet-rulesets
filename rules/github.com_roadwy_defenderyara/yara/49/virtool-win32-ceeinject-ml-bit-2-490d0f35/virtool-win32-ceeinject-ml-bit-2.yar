rule VirTool_Win32_CeeInject_ML_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.ML!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 55 90 83 c2 01 89 55 90 81 7d 90 88 13 00 00 7d 1c b8 5f 00 00 00 2b 45 98 8b 4d e0 03 c8 89 4d cc } 		$a_03_1 = {8b 4d 98 83 c1 01 89 4d 98 81 7d 98 ?? ?? ?? ?? 7d 5e 8d 55 a0 52 ff 15 ?? ?? ?? ?? 8b 45 b0 03 45 98 33 c9 8a 08 89 4d e0 } 		$a_01_2 = {6a 6b 67 61 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}