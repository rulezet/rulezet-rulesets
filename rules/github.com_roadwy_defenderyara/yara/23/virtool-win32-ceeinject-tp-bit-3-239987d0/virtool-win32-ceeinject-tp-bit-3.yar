rule VirTool_Win32_CeeInject_TP_bit_3{
	meta:
		description = "VirTool:Win32/CeeInject.TP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 83 c4 08 8b d1 8a 12 80 f2 81 88 10 ff 06 41 81 3e 2e 5b 00 00 75 } 		$a_03_1 = {55 8b ec 51 81 c2 4a 53 00 00 89 55 fc 8b 7d fc [0-10] 87 fb ff e3 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}