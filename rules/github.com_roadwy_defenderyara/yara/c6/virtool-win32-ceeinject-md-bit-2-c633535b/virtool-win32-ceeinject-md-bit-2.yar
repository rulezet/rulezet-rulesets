rule VirTool_Win32_CeeInject_MD_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.MD!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 51 52 e8 ?? ?? ?? ff 8b 54 ?? ?? a3 ?? ?? ?? 10 8b 44 ?? ?? 83 c4 14 8a 0c 30 32 cb 88 0c 16 46 83 fe 5e 0f 8c ?? ?? ?? ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}