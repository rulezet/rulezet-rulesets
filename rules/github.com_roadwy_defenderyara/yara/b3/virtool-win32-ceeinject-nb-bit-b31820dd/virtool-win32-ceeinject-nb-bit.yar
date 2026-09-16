rule VirTool_Win32_CeeInject_NB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.NB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 85 a4 df ff ff 25 ff 90 00 90 8b 4d fc 33 d2 8a 94 0d b4 d2 ff ff 33 c2 8b 4d fc } 		$a_03_1 = {70 f8 27 41 6a ?? 8d 95 d4 df ff ff ff } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}