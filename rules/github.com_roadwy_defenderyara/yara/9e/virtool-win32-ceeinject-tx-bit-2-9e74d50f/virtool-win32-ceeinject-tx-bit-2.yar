rule VirTool_Win32_CeeInject_TX_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TX!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f0 03 f3 73 05 e8 ?? ?? ?? ?? 8a 16 80 f2 4d 88 16 40 3d ?? ?? ?? ?? 75 e6 } 		$a_03_1 = {81 c3 a9 0a 00 00 73 05 e8 ?? ?? ?? ?? 89 5d fc ff 65 fc } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}