rule VirTool_Win32_CeeInject_GN{
	meta:
		description = "VirTool:Win32/CeeInject.GN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d9 c1 d8 c1 d8 c1 d8 e1 d8 e1 d8 c1 d8 c1 d8 c1 d8 c1 dd da d9 c1 dc 1d ?? ?? 40 00 df e0 9e 76 df } 		$a_03_1 = {8b de 8a 88 ?? ?? 40 00 8b 45 fc 99 f7 fb 32 0d ?? ?? 40 00 8b 5d 08 88 8c 05 58 eb ff ff 8a 8c 1d 58 eb ff ff 8d 84 1d 58 eb ff ff 80 f9 f2 77 04 fe c9 88 08 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}