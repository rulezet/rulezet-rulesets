rule VirTool_Win32_CeeInject_TP_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 37 5b f8 83 df fc f7 d3 83 eb 23 8d 5b ff 29 d3 89 da 89 1e f8 83 d6 04 83 c1 fc 85 c9 75 e0 } 		$a_01_1 = {5e 8d 05 04 10 49 00 ff 30 ff d6 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}