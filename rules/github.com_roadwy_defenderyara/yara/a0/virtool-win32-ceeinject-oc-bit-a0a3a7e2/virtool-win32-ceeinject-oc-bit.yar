rule VirTool_Win32_CeeInject_OC_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OC!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 db 33 1e 83 c6 ?? f7 d3 83 c3 ?? c1 cb ?? d1 c3 01 cb f8 83 d3 ?? 53 59 c1 c1 ?? d1 c9 89 1a 83 ea ?? f8 83 df ?? 81 ff ?? ?? ?? ?? 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}