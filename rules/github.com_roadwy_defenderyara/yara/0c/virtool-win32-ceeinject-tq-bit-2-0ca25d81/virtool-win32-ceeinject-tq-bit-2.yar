rule VirTool_Win32_CeeInject_TQ_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 f3 88 dd 88 4c 24 ?? 88 e9 8b 5c 24 ?? d3 e3 89 5c 24 ?? 8a 4c 24 ?? 88 0a 8b 54 24 ?? 81 c2 ?? ?? ?? ?? 8b 5c 24 ?? 83 d3 00 8b 7c 24 ?? 01 c7 } 		$a_03_1 = {8a 1c 11 8a bc 02 ?? ?? ?? ?? 28 fb 8b 44 24 ?? 88 1c 10 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}